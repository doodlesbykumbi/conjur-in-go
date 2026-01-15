package model

// Annotation represents metadata on a resource
type Annotation struct {
	ResourceID string `gorm:"column:resource_id;primaryKey"`
	Name       string `gorm:"column:name;primaryKey"`
	Value      string `gorm:"column:value;not null"`
}

func (Annotation) TableName() string {
	return "annotations"
}
