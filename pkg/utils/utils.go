package utils

import "encoding/json"

func ToJson(input interface{}) string {
	output, _ := json.Marshal(input)
	return string(output)
}
