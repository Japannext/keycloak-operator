package utils

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *BaseReconciler) AppendOwnerReferences(ctx context.Context, i, owner client.Object) error {
	refs := i.GetOwnerReferences()
	gvk := owner.GetObjectKind().GroupVersionKind()
	apiVersion := fmt.Sprintf("%s/%s", gvk.Group, gvk.Version)
	kind := gvk.Kind
	name := owner.GetName()
	uid := owner.GetUID()
	if len(refs) > 0 {
		ref := refs[0]
		if ref.APIVersion == apiVersion &&
			ref.Kind == kind &&
			ref.Name == name &&
			ref.UID == uid {
			return nil
		}
	}
	ownerReference := fmt.Sprintf(
		`{"apiVersion": "%s", "kind": "%s", "name": "%s", "uid": "%s", "controller": true, "blockOwnerDeletion": false}`,
		apiVersion, kind, name, uid,
	)
	text := fmt.Sprintf(`{"metadata": {"ownerReferences": [%s]}}`, ownerReference)
	patch := client.RawPatch(types.MergePatchType, []byte(text))
	if err := r.Patch(ctx, i, patch); err != nil {
		return fmt.Errorf("failed to patch resource (owner-reference): %w", err)
	}
	return nil
}
