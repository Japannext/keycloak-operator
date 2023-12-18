package utils

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/japannext/keycloak-operator/api/v1alpha2"
)

func makePatch(phase v1alpha2.Phase) client.Patch {
	t, _ := Now().MarshalJSON()
	text := fmt.Sprintf(`{"status": {"api": {"phase": "%s", "lastTransitionTime": %s}}}`, phase, string(t))
	return client.RawPatch(types.MergePatchType, []byte(text))
}

func makeCustomPatch(key, value string) client.Patch {
	text := fmt.Sprintf(`{"status": {"%s": "%s"}}`, key, value)
	return client.RawPatch(types.MergePatchType, []byte(text))
}

func (r *BaseReconciler) CustomPatch(ctx context.Context, i client.Object, key, value, previous string) error {
	if previous != value {
		patch := makeCustomPatch(key, value)
		if err := r.Status().Patch(ctx, i, patch); err != nil {
			return fmt.Errorf("failed to patch resource status (%s): %w", key, err)
		}
	}
	return nil
}
