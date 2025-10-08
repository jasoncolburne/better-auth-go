package api_test

import (
	"testing"

	"github.com/jasoncolburne/better-auth-go/examples/crypto"
	"github.com/jasoncolburne/better-auth-go/examples/encoding"
	"github.com/jasoncolburne/better-auth-go/pkg/messages"
)

func TestTokenParsing(t *testing.T) {
	tokenEncoder := encoding.NewTokenEncoder[MockAttributes]()

	tempTokenString := "0IAGTf0y29Ra-8cjCnXS8NlImAi4_KZfaxgr_5iAux1CLoOZ7d5tvFktxb8Xc6pU2pYQkMw0V75fwP537N9dToIyH4sIAAAAAAACA22PXY-iMBSG_wvX203rUBHuOgIDasQ1jC5uNobaKkU-TFtAZ-J_nzoXu8nOnsuT93k_3i3FZc9lzHijhb5ZnoUIiUl_mNkp0isAWHpgCzKMWSaghJvE309VxifT6_no3Nh1G1jfLMZ7ceCGDYJhvIoDqXySVCAcPdfc2VFYlHG-TabDa0leu1NE56Byc8OJv6lB0taqqFx5jGadHfUiTU9OHYrFXp17FmKIdpfMZk80ileGvHS0Eoc5_1P4jVIM1qW92Qb-7keC6-HlxZH-Yjm-Coxilm1Q2-AV3dPO4LLVuRZtE-WqeISHIZDEGWe125Z-BnVHxc9NuQZk3c-XziyS5-2ybt6OpyJ51Faq44xoQ47gCAMEAZykaORh17PR9wnG8PN2RsuvFyFv_yifPGR_UUp-lFwVwRfATSH8n3WutRS001xZ3rt14bI2xcwo9XxbtxV_PHNWi8byfhnznBlkkEJz6_f9fv8A44o2TvkBAAA"

	tempKey, err := crypto.NewSecp256r1()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	tempToken, err := messages.ParseAccessToken[MockAttributes](tempTokenString, tokenEncoder)
	if err != nil {
		t.Fatalf("Failed to parse temp token: %v", err)
	}

	newToken := messages.NewAccessToken(
		tempToken.ServerIdentity,
		tempToken.Device,
		tempToken.Identity,
		tempToken.PublicKey,
		tempToken.RotationHash,
		tempToken.IssuedAt,
		tempToken.Expiry,
		tempToken.RefreshExpiry,
		tempToken.Attributes,
	)

	if err := newToken.Sign(tempKey); err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	tokenString, err := newToken.SerializeToken(tokenEncoder)
	if err != nil {
		t.Fatalf("Failed to serialize token: %v", err)
	}

	token, err := messages.ParseAccessToken[MockAttributes](tokenString, tokenEncoder)
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	if token.ServerIdentity != "1AAIAvcJ4T1tP--dTcdLAw6dYi0r0VOD_CsYe8Cxkf7ydxWE" {
		t.Errorf("Expected server identity '1AAIAvcJ4T1tP--dTcdLAw6dYi0r0VOD_CsYe8Cxkf7ydxWE', got '%s'", token.ServerIdentity)
	}

	if token.Device != "EEw6PIErsDAOl-F2Bme7Zb0hjIaWOCwUjAUugHbK-l9a" {
		t.Errorf("Expected device 'EEw6PIErsDAOl-F2Bme7Zb0hjIaWOCwUjAUugHbK-l9a', got '%s'", token.Device)
	}

	if token.Identity != "EOomshl9rfHJu4HviTTg7mFiL_skvdF501ZpY4d3bHIP" {
		t.Errorf("Expected identity 'EOomshl9rfHJu4HviTTg7mFiL_skvdF501ZpY4d3bHIP', got '%s'", token.Identity)
	}

	if token.PublicKey != "1AAIAzbb5-Rj4VWEDZQO5mwGG7rDLN6xi51IdYV1on5Pb_bu" {
		t.Errorf("Expected public key '1AAIAzbb5-Rj4VWEDZQO5mwGG7rDLN6xi51IdYV1on5Pb_bu', got '%s'", token.PublicKey)
	}

	if token.RotationHash != "EFF-rA76Ym9ojDY0tubiXVjR-ARvKN7JHrkWNmnzfghO" {
		t.Errorf("Expected rotation hash 'EFF-rA76Ym9ojDY0tubiXVjR-ARvKN7JHrkWNmnzfghO', got '%s'", token.RotationHash)
	}

	if token.IssuedAt != "2025-10-08T12:59:41.855000000Z" {
		t.Errorf("Expected issued at '2025-10-08T12:59:41.855000000Z', got '%s'", token.IssuedAt)
	}

	if token.Expiry != "2025-10-08T13:14:41.855000000Z" {
		t.Errorf("Expected expiry '2025-10-08T13:14:41.855000000Z', got '%s'", token.Expiry)
	}

	if token.RefreshExpiry != "2025-10-09T00:59:41.855000000Z" {
		t.Errorf("Expected refresh expiry '2025-10-09T00:59:41.855000000Z', got '%s'", token.RefreshExpiry)
	}

	expectedPermissions := []string{"read", "write"}
	actualPermissions, ok := token.Attributes.PermissionsByRole["admin"]
	if !ok {
		t.Errorf("Expected 'admin' role in permissions, but it was not found")
	} else {
		if len(actualPermissions) != len(expectedPermissions) {
			t.Errorf("Expected %d permissions for 'admin', got %d", len(expectedPermissions), len(actualPermissions))
		}
		for i, perm := range expectedPermissions {
			if i >= len(actualPermissions) || actualPermissions[i] != perm {
				t.Errorf("Expected permission '%s' at index %d, got '%s'", perm, i, actualPermissions[i])
			}
		}
	}
}
