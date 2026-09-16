/*
 * @Description:
 * @LastEditors: ayu
 */
package logger

import "testing"

func TestLogger(t *testing.T) {
	InitLog("debug")
	Log.Debug("run Debug")
	Log.Info("run Info")
	Log.Warn("run Warn")
	SetDefault("", "debug")
	Log.Warn("run Warn")
	Log.Error("run Error")
	Log.Error("run", `{"aa":111}`)

}
