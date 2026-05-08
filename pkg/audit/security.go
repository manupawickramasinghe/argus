package audit

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// SignPayloadFunc is a strategy for signing payloads.
// It allows the client to provide its own signing logic (e.g. KMS, File-based, etc.)
// without exposing private keys to the audit library.
type SignPayloadFunc func(ctx context.Context, payload []byte) (signature string, err error)

// CanonicalizeRequest creates a deterministic byte representation of an AuditLogRequest
// for cryptographic signing and verification.
//
// IMPORTANT: This uses a pipe-delimited format instead of JSON serialization.
// json.Marshal output is Go-specific (spacing, key ordering of maps, encoding of
// special characters) and is extremely difficult to reproduce byte-for-byte in other
// languages like Python or Node.js. By using a simple pipe-delimited format, any
// language in NSW's polyglot ecosystem can trivially compute the same canonical payload.
//
// Canonical format (fields separated by "|"):
//
//	TraceID|Timestamp|EventType|Action|Status|ActorType|ActorID|TargetType|TargetID|Message|MetadataJSON
//
// Rules:
//   - nil/empty pointer fields use the empty string ""
//   - Message bytes are base64-encoded (standard encoding, no padding trimming)
//   - Metadata map is serialized via json.Marshal (maps have sorted keys in Go 1.8+),
//     but since this is a simple map[string]interface{}, most languages can reproduce it.
//     An empty/nil map serializes as "{}"
func CanonicalizeRequest(event *AuditLogRequest) ([]byte, error) {
	traceID := ""
	if event.TraceID != nil {
		traceID = *event.TraceID
	}

	targetID := ""
	if event.TargetID != nil {
		targetID = *event.TargetID
	}

	// Base64-encode message bytes for safe textual representation
	msgEncoded := base64.StdEncoding.EncodeToString(event.Message)

	// Serialize metadata deterministically
	metadataJSON := "{}"
	if event.Metadata != nil {
		metaBytes, err := json.Marshal(event.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata for canonicalization: %w", err)
		}
		metadataJSON = string(metaBytes)
	}

	escape := func(s string) string {
		return strings.ReplaceAll(s, "|", "\\|")
	}

	canonical := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		escape(traceID),
		escape(event.Timestamp),
		escape(event.EventType),
		escape(event.Action),
		escape(event.Status),
		escape(event.ActorType),
		escape(event.ActorID),
		escape(event.TargetType),
		escape(targetID),
		escape(msgEncoded),
		escape(metadataJSON),
	)

	return []byte(canonical), nil
}

// SignPayload hashes and signs the canonical payload using the provided signer.
func SignPayload(payload []byte, signer crypto.Signer) (string, string, error) {
	hash := sha256.Sum256(payload)

	switch signer.(type) {
	case *rsa.PrivateKey:
		sig, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
		if err != nil {
			return "", "", fmt.Errorf("rsa signing failed: %w", err)
		}
		return base64.StdEncoding.EncodeToString(sig), "RS256", nil
	case ed25519.PrivateKey:
		// Ed25519 ignores the hash if passed, or uses the full message.
		// Standard crypto.Signer.Sign for Ed25519 expects the original message, not a hash.
		sig, err := signer.Sign(rand.Reader, payload, crypto.Hash(0))
		if err != nil {
			return "", "", fmt.Errorf("ed25519 signing failed: %w", err)
		}
		return base64.StdEncoding.EncodeToString(sig), "EdDSA", nil
	default:
		return "", "", errors.New("unsupported signer type (only RSA and Ed25519 are supported)")
	}
}

// VerifyPayload verifies the signature of the payload using the provided public key
func VerifyPayload(payload []byte, signatureBase64 string, alg string, publicKey crypto.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return fmt.Errorf("invalid base64 signature: %w", err)
	}

	hash := sha256.Sum256(payload)

	switch pk := publicKey.(type) {
	case *rsa.PublicKey:
		if alg != "RS256" {
			return fmt.Errorf("algorithm mismatch: expected RS256 for RSA public key, got %s", alg)
		}
		err := rsa.VerifyPKCS1v15(pk, crypto.SHA256, hash[:], sig)
		if err != nil {
			return fmt.Errorf("rsa verification failed: %w", err)
		}
		return nil
	case ed25519.PublicKey:
		if alg != "EdDSA" {
			return fmt.Errorf("algorithm mismatch: expected EdDSA for Ed25519 public key, got %s", alg)
		}
		if !ed25519.Verify(pk, payload, sig) {
			return errors.New("ed25519 verification failed")
		}
		return nil
	default:
		return errors.New("unsupported public key type (only RSA and Ed25519 are supported)")
	}
}
