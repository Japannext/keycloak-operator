package utils

import (
	"fmt"
	"testing"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/stretchr/testify/assert"
)

func TestRescheduleAfter(t *testing.T) {
	e := RescheduleAfter(1*time.Minute, fmt.Errorf("test"))
	assert := assert.New(t)
	res, err := HandleError(e)
	assert.Equal(1*time.Minute, res.RequeueAfter, "requeue after 1 minute")
	assert.NoError(err, "no error")
}

func TestDoNotReschedule(t *testing.T) {
	e := DoNotReschedule(fmt.Errorf("test"))
	assert := assert.New(t)
	res, err := HandleError(e)
	assert.Equal(ctrl.Result{}, res, "no requeue")
	assert.NoError(err, "no error")
}
