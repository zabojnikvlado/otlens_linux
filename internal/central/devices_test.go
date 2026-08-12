package central

import "testing"

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
