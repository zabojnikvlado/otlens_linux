package central

import (
	"strings"
	"testing"
)

func TestNormalizeAssetCategoryAcceptsEveryUICategory(t *testing.T) {
	for _, category := range assetCategories {
		got, ok := normalizeAssetCategory(category)
		if !ok || got != category {
			t.Fatalf("category %q rejected or changed: %q ok=%t", category, got, ok)
		}
	}
	if got, ok := normalizeAssetCategory(" engineering workstation "); !ok || got != "Engineering Workstation" {
		t.Fatalf("case-insensitive imported category not canonicalized: %q ok=%t", got, ok)
	}
	if _, ok := normalizeAssetCategory("arbitrary"); ok {
		t.Fatal("unknown category accepted")
	}
}

func TestValidateAssetCategoryName(t *testing.T) {
	if got, err := validateAssetCategoryName("  Packaging Line  "); err != nil || got != "Packaging Line" {
		t.Fatalf("custom category not normalized: got=%q err=%v", got, err)
	}
	if _, err := validateAssetCategoryName("\n"); err == nil {
		t.Fatal("control/empty custom category accepted")
	}
	if _, err := validateAssetCategoryName(strings.Repeat("a", 65)); err == nil {
		t.Fatal("oversized custom category accepted")
	}
}
