//go:build !windows

package common

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// instanceLockFile 持有锁文件句柄。必须是包级变量：
// os.File 一旦失去引用会被 GC 关闭 fd 并释放 flock，锁就失效了。
var instanceLockFile *os.File

// LockInstance 对 path 加进程级非阻塞排他锁，用于防止同一份配置被两个进程同时托管。
// 进程退出（含崩溃）时由内核自动释放，不会留下死锁。
func LockInstance(path string) error {
	if instanceLockFile != nil {
		return nil
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("打开锁文件 %s 失败: %w", path, err)
	}

	if lockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); lockErr != nil {
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
