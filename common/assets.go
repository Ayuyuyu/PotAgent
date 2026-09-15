package common

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/duke-git/lancet/v2/fileutil"
	"potAgent/logger"
)

// assetsArchiveName 是服务资源压缩包在 services 目录下的固定文件名。
const assetsArchiveName = "assets.zip"

// EnsureAssets 在 services 目录下按需解压资源包。
// 仅当目标资源目录 (servicesDir/assets) 不存在时才解压，避免覆盖本地修改。
func EnsureAssets(servicesDir string) error {
	assetsDir := filepath.Join(servicesDir, "assets")
	if fileutil.IsExist(assetsDir) {
		return nil
	}
	zipPath := filepath.Join(servicesDir, assetsArchiveName)
	if !fileutil.IsExist(zipPath) {
		logger.Log.Warnf("未找到资源包 %s，跳过解压", zipPath)
		return nil
	}
	logger.Log.Infof("解压资源包 %s -> %s", zipPath, assetsDir)
	return ExtractZip(zipPath, servicesDir)
}

// ExtractZip 将 zip 压缩包解压到 destDir，防止目录穿越（zip-slip）。
func ExtractZip(zipPath, destDir string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	dest := filepath.Clean(destDir)

	for _, f := range reader.File {
		name := f.Name

		// 防止 zip-slip：拒绝绝对路径或包含 ../ 的条目
		target := filepath.Join(dest, name)
		if !strings.HasPrefix(target, dest+string(filepath.Separator)) {
			return fmt.Errorf("illegal entry in zip: %s", name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}

		// 确保父目录存在
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}

		in, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode().Perm())
		if err != nil {
			in.Close()
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			in.Close()
			out.Close()
			return err
		}
		in.Close()
		out.Close()
	}
	return nil
}
