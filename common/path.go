package common

import (
	"fmt"
	"os"
	"path/filepath"
	"potAgent/logger"
	"runtime"
	"strings"

	"github.com/duke-git/lancet/v2/fileutil"
)

func InsertDirIfNotAbsolutePath(filePath string) (path string) {
	if filepath.IsAbs(filePath) {
		return filePath
	} else {
		absPath := fileutil.CurrentPath()
		path = filepath.Join(absPath, filePath)
		return path
	}
}

func FindConfigFile(confDir string) ([]string, error) {
	if !fileutil.IsExist(confDir) {
		return []string{}, fmt.Errorf("%s not exist", confDir)
	}
	var files []string
	// 处理一下dir的末尾字符
	if !strings.HasSuffix(confDir, "/") && !strings.HasSuffix(confDir, "\\") {
		if runtime.GOOS == "windows" {
			confDir += "\\"
		} else {
			confDir += "/"
		}
	}
	//confDir += "/"
	logger.Log.Info("正在读取目录", confDir)
	err := filepath.Walk(confDir, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".yaml") {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

func GetAllFile(dstDir string) ([]string, error) {
	var fl []string
	err := filepath.Walk(dstDir, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			panic(fmt.Sprintf("found nil, check the path wether exist, %v", path))
		}
		if f.IsDir() {
			if path == dstDir {
				return nil
			}
			subfl, err := GetAllFile(path)
			if err != nil {
				return err
			}
			fl = append(fl, subfl...)
		} else {
			fl = append(fl, path)
		}

		return nil
	})

	return fl, err
}

func GetSubDirectory(dstDir string, depth int) ([]string, error) {
	var dl []string
	dirs, err := os.ReadDir(dstDir)
	if err != nil {
		return nil, err
	}

	for _, d := range dirs {
		dl = append(dl, d.Name())
	}

	return dl, err
}
