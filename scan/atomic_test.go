package scan

import "sync/atomic"

func addInt(p *int32, d int32) int32   { return atomic.AddInt32(p, d) }
func loadInt(p *int32) int32           { return atomic.LoadInt32(p) }
func casInt(p *int32, o, n int32) bool { return atomic.CompareAndSwapInt32(p, o, n) }
