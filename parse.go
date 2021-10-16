package m3u8

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
)

type M3u8 struct {
	Segments  []Segment
	PlayInfos []PlayInfo
}

type PlayInfo struct {
	M3u8Url    string
	ProgramId  int64
	BandWidth  int64
	Resolution Resolution
}

type Resolution struct {
	Width int64
	High  int64
}

// Ts文件元信息
type Segment struct {
	Idx         int
	Url         string
	ErrMsg      string
	EncryptMeta EncryptMeta
}

func (s Segment) IsEncrypted() bool {
	return s.EncryptMeta.Method == CryptMethodAES
}

type EncryptMeta struct {
	SecretKeyUrl string
	IV           string
	Method       string
	SecretKey    string
}

const (
	CryptMethodAES  = "AES-128"
	CryptMethodNONE = "NONE"
)

var paramPattern = regexp.MustCompile(`([a-zA-Z-]+)=("[^"]+"|[^",]+)`)

// 注意Parse不会填充SecretKey
func Parse(lines []string, m3u8Url *url.URL) (*M3u8, error) {
	if m3u8Url == nil || !m3u8Url.IsAbs() {
		return nil, errors.New("m3u8Url is not absolute url")
	}

	if !(len(lines) >= 1 && strings.TrimSpace(lines[0]) == "#EXTM3U") {
		return nil, errors.New("line:0, not begin with #EXTM3U")
	}

	var (
		ret         = &M3u8{}
		encryptMeta EncryptMeta
	)

	for i := 1; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		switch {
		case l == "":
		case strings.HasPrefix(l, "#EXT-X-STREAM-INF:"):
			play := PlayInfo{}
			for {
				params := toParam(l)
				if v, ok := params["PROGRAM-ID"]; ok {
					pid, err := strconv.ParseInt(v, 10, 64)
					if err != nil {
						return nil, fmt.Errorf("line:%d, PROGRAM-ID(%s) is not a number, %w", i, v, err)
					}
					play.ProgramId = pid
				}
				if v, ok := params["BANDWIDTH"]; ok {
					bandWidth, err := strconv.ParseInt(v, 10, 64)
					if err != nil {
						return nil, fmt.Errorf("line:%d, BANDWIDTH(%s) is not a number, %w", i, v, err)
					}
					play.BandWidth = bandWidth
				}
				if v, ok := params["RESOLUTION"]; ok {
					arr := strings.Split(v, "x")
					if len(arr) != 2 {
						return nil, fmt.Errorf("line:%d, RESOLUTION(%s) is illegal", i, v)
					}
					width, err := strconv.ParseInt(arr[0], 10, 64)
					if err != nil {
						return nil, fmt.Errorf("line:%d, RESOLUTION(%s) is illegal, %w", i, v, err)
					}
					high, err := strconv.ParseInt(arr[1], 10, 64)
					if err != nil {
						return nil, fmt.Errorf("line:%d, RESOLUTION(%s) is illegal, %w", i, v, err)
					}
					play.Resolution.Width = width
					play.Resolution.High = high
				}

				if !continueWithNextLine(l) {
					break
				}
				i++
				l = strings.TrimSpace(lines[i])
			}

			i++
			l = strings.TrimSpace(lines[i])
			u, err := toUrl(l, m3u8Url)
			if err != nil {
				return nil, fmt.Errorf("line:%d, sub m3u8 url(%s) is illegal, %w", i, l, err)
			}
			play.M3u8Url = u.String()
			ret.PlayInfos = append(ret.PlayInfos, play)
		case strings.HasPrefix(l, "#EXT-X-KEY"):
			encryptMeta = EncryptMeta{}
			for {
				params := toParam(l)
				if v, ok := params["METHOD"]; ok {
					if v != CryptMethodAES && v != CryptMethodNONE {
						return nil, fmt.Errorf("line:%d, unknown encrypt method %s", i, v)
					}
					encryptMeta.Method = v
				}
				if v, ok := params["URI"]; ok {
					u, err := toUrl(v, m3u8Url)
					if err != nil {
						return nil, fmt.Errorf("line:%d, URI(%s) is illegal, %w", i, v, err)
					}
					encryptMeta.SecretKeyUrl = u.String()
				}
				if v, ok := params["IV"]; ok {
					encryptMeta.IV = v
				}

				if !continueWithNextLine(l) {
					break
				}
				i++
				l = strings.TrimSpace(lines[i])
			}
		case strings.HasPrefix(l, "#"):
			for {
				if !continueWithNextLine(l) {
					break
				}
				i++
				l = strings.TrimSpace(lines[i])
			}
		default:
			seg := Segment{}
			u, err := toUrl(l, m3u8Url)
			if err != nil {
				return nil, fmt.Errorf("line:%d, ts file url(%s) is illegal, %w", i, l, err)
			}
			seg.Idx = len(ret.Segments)
			seg.Url = u.String()
			seg.EncryptMeta = encryptMeta
			ret.Segments = append(ret.Segments, seg)
		}
	}
	return ret, nil
}

// line必须是去除前导和尾随空格后的结果
func continueWithNextLine(l string) bool {
	g := len(l)
	return g >= 2 && l[g-1] == '\\' && l[g-2] == ' '
}

func toParam(l string) map[string]string {
	r := paramPattern.FindAllStringSubmatch(l, -1)
	ret := make(map[string]string)
	for _, v := range r {
		ret[v[1]] = strings.Trim(strings.Trim(v[2], "\""), "\"")
	}
	return ret
}

func toUrl(uri string, m3u8Url *url.URL) (*url.URL, error) {
	if strings.HasPrefix(uri, "https://") || strings.HasPrefix(uri, "http://") {
		ret, err := url.Parse(uri)
		if err != nil {
			return nil, fmt.Errorf("uri(%s) is not illegal, %w", uri, err)
		}
		return ret, nil
	}

	var prefix string
	if uri[0] == '/' {
		prefix = m3u8Url.Scheme + "://" + m3u8Url.Host
	} else {
		v := m3u8Url.String()
		prefix = v[0:strings.LastIndex(v, "/")]
	}
	u := prefix + path.Join("/", uri)

	ret, err := url.Parse(u)
	if err != nil {
		return nil, fmt.Errorf("uri(%s) is not illegal, %w", uri, err)
	}

	return ret, nil
}
