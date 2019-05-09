package check

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToJson(t *testing.T) {
	var p Params
	assert.NoError(t, p.fill(""), "should have no error filling params")
	body, err := json.Marshal(p)
	assert.NoError(t, err, "should have no error marshalling params to JSON")
	_ = body
	t.Logf("JSON is: %+v", string(body))
}
