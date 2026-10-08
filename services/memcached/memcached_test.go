package memcached

import (
	"strings"
	"testing"
)

func newStore() *memcachedStore { return newMemcachedStore() }

func TestSetGet(t *testing.T) {
	s := newStore()
	if r := s.cmdSet("k1", 12, 0, []byte("hello")); r != "STORED\r\n" {
		t.Fatalf("set: %q", r)
	}
	got := s.getMulti([]string{"k1"}, false)
	if !strings.Contains(got, "VALUE k1 12 5\r\nhello\r\n") || !strings.HasSuffix(got, "END\r\n") {
		t.Fatalf("get: %q", got)
	}
	// 不存在的 key 仅返回 END
	if got := s.getMulti([]string{"nope"}, false); got != "END\r\n" {
		t.Fatalf("get missing: %q", got)
	}
}

func TestAddReplace(t *testing.T) {
	s := newStore()
	if r := s.cmdAdd("k", 0, 0, []byte("v1")); r != "STORED\r\n" {
		t.Fatalf("add new: %q", r)
	}
	if r := s.cmdAdd("k", 0, 0, []byte("v2")); r != "NOT_STORED\r\n" {
		t.Fatalf("add dup: %q", r)
	}
	if r := s.cmdReplace("missing", 0, 0, []byte("x")); r != "NOT_STORED\r\n" {
		t.Fatalf("replace missing: %q", r)
	}
	if r := s.cmdReplace("k", 0, 0, []byte("v3")); r != "STORED\r\n" {
		t.Fatalf("replace: %q", r)
	}
	if got := s.getMulti([]string{"k"}, false); !strings.Contains(got, "v3") {
		t.Fatalf("replace value: %q", got)
	}
}

func TestAppendPrepend(t *testing.T) {
	s := newStore()
	s.cmdSet("k", 0, 0, []byte("mid"))
	if r := s.cmdAppend("k", []byte("-end")); r != "STORED\r\n" {
		t.Fatalf("append: %q", r)
	}
	if r := s.cmdPrepend("k", []byte("start-")); r != "STORED\r\n" {
		t.Fatalf("prepend: %q", r)
	}
	if got := s.getMulti([]string{"k"}, false); !strings.Contains(got, "start-mid-end") {
		t.Fatalf("append/prepend value: %q", got)
	}
	if r := s.cmdAppend("missing", []byte("x")); r != "NOT_STORED\r\n" {
		t.Fatalf("append missing: %q", r)
	}
}

func TestCas(t *testing.T) {
	s := newStore()
	s.cmdSet("k", 0, 0, []byte("v1"))
	// 错误 cas token
	if r := s.cmdCas("k", 0, 0, []byte("v2"), 999); r != "EXISTS\r\n" {
		t.Fatalf("cas wrong token: %q", r)
	}
	// 正确 token（set 后 cas=1）
	if r := s.cmdCas("k", 0, 0, []byte("v3"), 1); r != "STORED\r\n" {
		t.Fatalf("cas ok: %q", r)
	}
	if got := s.getMulti([]string{"k"}, false); !strings.Contains(got, "v3") {
		t.Fatalf("cas value: %q", got)
	}
	if r := s.cmdCas("missing", 0, 0, []byte("x"), 1); r != "NOT_FOUND\r\n" {
		t.Fatalf("cas missing: %q", r)
	}
}

func TestDelete(t *testing.T) {
	s := newStore()
	if r := s.cmdDelete("missing"); r != "NOT_FOUND\r\n" {
		t.Fatalf("delete missing: %q", r)
	}
	s.cmdSet("k", 0, 0, []byte("v"))
	if r := s.cmdDelete("k"); r != "DELETED\r\n" {
		t.Fatalf("delete: %q", r)
	}
	if r := s.cmdDelete("k"); r != "NOT_FOUND\r\n" {
		t.Fatalf("delete again: %q", r)
	}
}

func TestIncrDecr(t *testing.T) {
	s := newStore()
	s.cmdSet("n", 0, 0, []byte("10"))
	if r := s.cmdIncrDecr("n", "5", false); r != "15\r\n" {
		t.Fatalf("incr: %q", r)
	}
	if r := s.cmdIncrDecr("n", "3", true); r != "12\r\n" {
		t.Fatalf("decr: %q", r)
	}
	// decr 不跌破 0
	s.cmdSet("z", 0, 0, []byte("2"))
	if r := s.cmdIncrDecr("z", "5", true); r != "0\r\n" {
		t.Fatalf("decr floor: %q", r)
	}
	if r := s.cmdIncrDecr("missing", "1", false); r != "NOT_FOUND\r\n" {
		t.Fatalf("incr missing: %q", r)
	}
	s.cmdSet("bad", 0, 0, []byte("abc"))
	if !strings.HasPrefix(s.cmdIncrDecr("bad", "1", false), "CLIENT_ERROR") {
		t.Fatalf("incr non-numeric should error")
	}
}

func TestFlush(t *testing.T) {
	s := newStore()
	s.cmdSet("k", 0, 0, []byte("v"))
	if r := s.cmdFlush(); r != "OK\r\n" {
		t.Fatalf("flush: %q", r)
	}
	if got := s.getMulti([]string{"k"}, false); got != "END\r\n" {
		t.Fatalf("after flush: %q", got)
	}
}

func TestVersionStats(t *testing.T) {
	if v := versionString("1.6.21"); v != "VERSION 1.6.21\r\n" {
		t.Fatalf("version: %q", v)
	}
	s := newStore()
	s.cmdSet("k", 7, 0, []byte("123"))
	st := s.statsString("1.6.21")
	if !strings.Contains(st, "STAT version 1.6.21\r\n") ||
		!strings.Contains(st, "STAT curr_items 1\r\n") ||
		!strings.HasSuffix(st, "END\r\n") {
		t.Fatalf("stats: %q", st)
	}
}

func TestGetsCasToken(t *testing.T) {
	s := newStore()
	s.cmdSet("k", 0, 0, []byte("v"))
	got := s.getMulti([]string{"k"}, true)
	if !strings.Contains(got, "VALUE k 0 1 1\r\n") {
		t.Fatalf("gets cas token: %q", got)
	}
}

func TestHandleNonStorageUnknown(t *testing.T) {
	s := newStore()
	reply, close := handleNonStorage(s, "FOOBAR", []string{"FOOBAR"}, "1.6.21")
	if reply != "ERROR\r\n" || close {
		t.Fatalf("unknown: reply=%q close=%v", reply, close)
	}
	if _, close := handleNonStorage(s, "QUIT", []string{"QUIT"}, "1.6.21"); !close {
		t.Fatalf("quit should close")
	}
}
