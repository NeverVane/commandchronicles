package config

import (
	"time"
)

// TagColorCodes defines the available colors for tags
var TagColorCodes = []string{
	"#888888", // gray (instead of black for dark mode)
	"#FF0000", // red
	"#00FF00", // green
	"#FFFF00", // yellow
	"#0000FF", // blue
	"#FF00FF", // magenta
	"#00FFFF", // cyan
	"#FFFFFF", // white
	"#A0A0A0", // light gray
	"#FF8080", // bright red
	"#80FF80", // bright green
	"#FFFF80", // bright yellow
	"#8080FF", // bright blue
	"#FF80FF", // bright magenta
	"#80FFFF", // bright cyan
	"#F0F0F0", // bright white
}

// TagColorNames provides human-readable names for colors (for UI display)
var TagColorNames = []string{
	"Gray",
	"Red",
	"Green",
	"Yellow",
	"Blue",
	"Magenta",
	"Cyan",
	"White",
	"Light Gray",
	"Bright Red",
	"Bright Green",
	"Bright Yellow",
	"Bright Blue",
	"Bright Magenta",
	"Bright Cyan",
	"Bright White",
}

// DefaultTagColor is the default color for new tags
const DefaultTagColor = "#00FFFF" // cyan

// GetTagColor returns the color for a given tag name, checking command override first,
// then global preferences, then default color
func (c *Config) GetTagColor(tagName string, commandTagColors map[string]string) string {
	// First check command-specific override
	if commandTagColors != nil {
		if color, exists := commandTagColors[tagName]; exists {
			return color
		}
	}

	// Then check global preferences
	if color, exists := c.Tags.TagColors[tagName]; exists {
		return color
	}

	// Finally, use default color
	return c.Tags.DefaultColor
}

// SetTagColor sets the color for a tag in global preferences
func (c *Config) SetTagColor(tagName, color string) {
	if c.Tags.TagColors == nil {
		c.Tags.TagColors = make(map[string]string)
	}
	if c.Tags.TagColorsUpdated == nil {
		c.Tags.TagColorsUpdated = make(map[string]int64)
	}

	c.Tags.TagColors[tagName] = color
	c.Tags.TagColorsUpdated[tagName] = time.Now().Unix()
}

// GetTagColorIndex returns the index of a color in TagColorCodes, or -1 if not found
func GetTagColorIndex(colorCode string) int {
	for i, code := range TagColorCodes {
		if code == colorCode {
			return i
		}
	}
	return -1
}

// IsValidTagColor checks if a color code is valid
func IsValidTagColor(colorCode string) bool {
	return GetTagColorIndex(colorCode) != -1
}

// GetTagColorName returns the human-readable name for a color code
func GetTagColorName(colorCode string) string {
	index := GetTagColorIndex(colorCode)
	if index >= 0 && index < len(TagColorNames) {
		return TagColorNames[index]
	}
	return "Unknown"
}

// GetTagColorByIndex returns the color code for a given index
func GetTagColorByIndex(index int) string {
	if index >= 0 && index < len(TagColorCodes) {
		return TagColorCodes[index]
	}
	return DefaultTagColor
}

// GetAllTagColors returns all available tag colors with their names
func GetAllTagColors() []struct {
	Code  string
	Name  string
	Index int
} {
	colors := make([]struct {
		Code  string
		Name  string
		Index int
	}, len(TagColorCodes))

	for i, code := range TagColorCodes {
		colors[i] = struct {
			Code  string
			Name  string
			Index int
		}{
			Code:  code,
			Name:  TagColorNames[i],
			Index: i,
		}
	}

	return colors
}

// CleanupOldTagColors removes tag colors that haven't been used recently
func (c *Config) CleanupOldTagColors(maxAge time.Duration) {
	if c.Tags.TagColorsUpdated == nil {
		return
	}

	cutoff := time.Now().Add(-maxAge).Unix()
	for tagName, lastUpdated := range c.Tags.TagColorsUpdated {
		if lastUpdated < cutoff {
			delete(c.Tags.TagColors, tagName)
			delete(c.Tags.TagColorsUpdated, tagName)
		}
	}
}

// GetTagColorPreferences returns all currently set tag color preferences
func (c *Config) GetTagColorPreferences() map[string]string {
	if c.Tags.TagColors == nil {
		return make(map[string]string)
	}

	// Return a copy to prevent external modification
	result := make(map[string]string)
	for k, v := range c.Tags.TagColors {
		result[k] = v
	}
	return result
}

// HasTagColorPreference checks if a tag has a color preference set
func (c *Config) HasTagColorPreference(tagName string) bool {
	if c.Tags.TagColors == nil {
		return false
	}
	_, exists := c.Tags.TagColors[tagName]
	return exists
}

// RemoveTagColorPreference removes a tag color preference
func (c *Config) RemoveTagColorPreference(tagName string) {
	if c.Tags.TagColors != nil {
		delete(c.Tags.TagColors, tagName)
	}
	if c.Tags.TagColorsUpdated != nil {
		delete(c.Tags.TagColorsUpdated, tagName)
	}
}
