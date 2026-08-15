package tail

import (
	"bufio"
	"context"
	"io"
	"os"
	"time"
)

// Follow appends of a file (and rotation: if size shrinks, rewind to 0).
// fromStart=false starts at EOF so we only see new lines.
func Follow(ctx context.Context, path string, fromStart bool, emit func(line string)) error {
	var f *os.File
	var err error
	var off int64
	var buf []byte

	open := func() error {
		if f != nil {
			f.Close()
			f = nil
		}
		f, err = os.Open(path)
		if err != nil {
			return err
		}
		if !fromStart {
			off, err = f.Seek(0, io.SeekEnd)
			if err != nil {
				return err
			}
			fromStart = true // subsequent reopen (rotation) reads from start of new file
		} else {
			off = 0
		}
		buf = buf[:0]
		return nil
	}

	for {
		if f == nil {
			if err := open(); err != nil {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(500 * time.Millisecond):
					continue
				}
			}
		}

		st, err := f.Stat()
		if err != nil {
			f.Close()
			f = nil
			continue
		}
		if st.Size() < off {
			// truncated / rotated
			off = 0
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				f.Close()
				f = nil
				continue
			}
			buf = buf[:0]
		}

		if st.Size() > off {
			if _, err := f.Seek(off, io.SeekStart); err != nil {
				f.Close()
				f = nil
				continue
			}
			r := bufio.NewReader(f)
			for {
				chunk, e := r.ReadBytes('\n')
				off += int64(len(chunk))
				buf = append(buf, chunk...)
				if len(buf) > 0 && buf[len(buf)-1] == '\n' {
					line := string(trimNL(buf))
					buf = buf[:0]
					if line != "" {
						emit(line)
					}
				}
				if e != nil {
					break
				}
			}
		}

		select {
		case <-ctx.Done():
			if f != nil {
				f.Close()
			}
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
