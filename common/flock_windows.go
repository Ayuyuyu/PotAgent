//go:build windows

package common

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
)

// instanceLockFile 持有锁文件句柄。必须是包级变量：
// os.File 一旦失去引用会被 GC 关闭句柄并释放锁，锁就失效了。
var instanceLockFile *os.File

// LockInstance 对 path 加进程级非阻塞排他锁（Windows 没有 flock，用 LockFileEx 锁首字节）。
// 进程退出（含崩溃）时由系统释放。
func LockInstance(path string) error {
	if instanceLockFile != nil {
		return nil
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("打开锁文件 %s 失败: %w", path, err)
	}

	overlapped := new(windows.Overlapped)
	lockErr := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, overlapped,
	)
	if lockErr != nil {
		existingPid, _ := os.ReadFile(path)
		_ = file.Close()

		if pid := strings.TrimSpace(string(existingPid)); pid != "" {
			return fmt.Errorf("已有 PotAgent 实例在运行（pid=%s，锁文件 %s）", pid, path)
		}

		return fmt.Errorf("已有 PotAgent 实例在运行（锁文件 %s）", path)
	}

	// 抢到锁后写入当前 pid，方便排查时确认是谁占着
	if truncErr := file.Truncate(0); truncErr == nil {
		_, _ = file.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}

	instanceLockFile = file

	return nil
}
