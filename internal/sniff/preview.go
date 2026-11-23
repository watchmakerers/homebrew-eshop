package sniff

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Preview is a browser view of the shop built from the exact replies the console gets (directories, directory,
// title, online_prices, images), for checking categories and artwork without a 3DS.
func (s *Shop) Preview() http.Handler {
	const host = "samurai.ctr.shop.preview"
	imgPrefix := imgBase(host)
	rewrite := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte(imgPrefix), []byte("/img")) }
	decode := func(r *stubReply, v any) bool { return r != nil && json.Unmarshal(rewrite(r.body), v) == nil }
	pretty := func(r *stubReply) string {
		if r == nil {
			return "(no reply: the console would get a 404)"
		}
		var buf bytes.Buffer
		if json.Indent(&buf, r.body, "", "  ") != nil {
			return string(r.body)
		}
		return buf.String()
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/img/", func(w http.ResponseWriter, r *http.Request) {
		rep := s.image(strings.TrimPrefix(r.URL.Path, "/img"))
		if rep == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", rep.contentType)
		w.Header().Set("Cache-Control", "max-age=300")
		w.Write(rep.body)
	})

	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		rep := s.directories(host)
		var v struct {
			Directories struct {
				Directory []struct {
					ID     int64  `json:"id"`
					Name   string `json:"name"`
					Icon   string `json:"icon_url"`
					Banner string `json:"banner_url"`
					New    bool   `json:"new"`
				} `json:"directory"`
			} `json:"directories"`
		}
		decode(rep, &v)
		render(w, "home", map[string]any{"Dirs": v.Directories.Directory, "Telops": s.Telops(), "Raw": pretty(rep)})
	})

	mux.HandleFunc("/d/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		const per = 60
		rep := s.directory(host, id, url.Values{"offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(per)}})
		var v struct {
			Directory struct {
				Name     string `json:"name"`
				Banner   string `json:"banner_url"`
				Contents struct {
					Total   int `json:"total"`
					Content []struct {
						Index int `json:"index"`
						Title struct {
							ID        int64  `json:"id"`
							Name      string `json:"name"`
							Icon      string `json:"icon_url"`
							Genre     string `json:"display_genre"`
							Date      string `json:"release_date_on_eshop"`
							New       bool   `json:"new"`
							Publisher struct {
								Name string `json:"name"`
							} `json:"publisher"`
						} `json:"title"`
					} `json:"content"`
				} `json:"contents"`
			} `json:"directory"`
		}
		if !decode(rep, &v) {
			http.NotFound(w, r)
			return
		}
		total := v.Directory.Contents.Total
		data := map[string]any{"ID": id, "Dir": v.Directory, "Raw": pretty(rep), "From": offset + 1,
			"To": min(offset+per, total), "Total": total}
		if offset > 0 {
			data["Prev"] = max(offset-per, 0)
		}
		if offset+per < total {
			data["Next"] = offset + per
		}
		render(w, "dir", data)
	})

	mux.HandleFunc("/t/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		rep := s.title(host, id)
		var v struct {
			Title struct {
				ID          int64  `json:"id"`
				Name        string `json:"name"`
				ProductCode string `json:"product_code"`
				TitleID     string `json:"title_id"`
				Icon        string `json:"icon_url"`
				Banner      string `json:"banner_url"`
				Description string `json:"description"`
				Disclaimer  string `json:"disclaimer"`
				Genre       string `json:"display_genre"`
				Date        string `json:"release_date_on_eshop"`
				Sales       bool   `json:"eshop_sales"`
				Download    bool   `json:"downloadable"`
				Publisher   struct {
					Name string `json:"name"`
				} `json:"publisher"`
			} `json:"title"`
		}
		if !decode(rep, &v) {
			http.NotFound(w, r)
			return
		}
		price := s.onlinePrices("US", url.Values{"title[]": {strconv.Itoa(id)}})
		status := ""
		var pv struct {
			OnlinePrices struct {
				OnlinePrice []struct {
					Status string `json:"eshop_sales_status"`
				} `json:"online_price"`
			} `json:"online_prices"`
		}
		if decode(price, &pv) && len(pv.OnlinePrices.OnlinePrice) > 0 {
			status = pv.OnlinePrices.OnlinePrice[0].Status
		}
		render(w, "title", map[string]any{"T": v.Title, "Status": status, "Raw": pretty(rep), "RawPrice": pretty(price),
			"Back": r.URL.Query().Get("from")})
	})
	return mux
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := previewTmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

var previewTmpl = template.Must(template.New("").Parse(`
{{define "head"}}<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Shop preview</title>
<style>
:root{--bg:#eef0f3;--fg:#1c2330;--muted:#5d6878;--card:#fff;--line:#d5dae1;--accent:#e8730c}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e6e9ee;--muted:#98a2b0;--card:#1f242b;--line:#323942}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:16px}
a{color:inherit;text-decoration:none}h1{font-size:20px;margin:4px 0 12px}
.top{display:block;width:100%;max-width:400px;aspect-ratio:400/240;object-fit:contain;background:#000;border-radius:10px;margin:0 auto 12px}
.ticker{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin-bottom:14px;color:var(--muted);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px;text-align:center;position:relative}
.tile img{width:100%;aspect-ratio:128/96;object-fit:contain;border-radius:6px;background:#fff}
.tile span{display:block;margin-top:6px;font-size:13px}
.new{position:absolute;top:6px;right:6px;background:var(--accent);color:#fff;font-size:11px;padding:1px 6px;border-radius:6px}
.list a{display:flex;gap:12px;align-items:center;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px;margin-bottom:8px}
.list img{width:56px;height:56px;object-fit:contain;border-radius:6px;background:#fff;flex:none}
.list small,.meta{color:var(--muted);font-size:12.5px}
.pager{display:flex;justify-content:space-between;margin:12px 0}
.desc{white-space:pre-wrap;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:6px;background:var(--line);font-size:12px;margin-right:6px}
details{margin-top:18px}pre{overflow:auto;font-size:11.5px;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px;max-height:420px}
.crumb{font-size:13px;color:var(--muted);margin-bottom:8px;display:inline-block}
</style></head><body><main>{{end}}
{{define "foot"}}</main></body></html>{{end}}

{{define "home"}}{{template "head"}}
<h1>Shop preview</h1>
<div class="ticker">{{range .Telops}}{{.}} &nbsp;·&nbsp; {{end}}</div>
<div class="grid">{{range .Dirs}}<a class="tile" href="/d/{{.ID}}">{{if .New}}<i class="new">New</i>{{end}}
<img src="{{.Icon}}" alt="" loading="lazy"><span>{{.Name}}</span></a>{{end}}</div>
<details><summary>directories reply</summary><pre>{{.Raw}}</pre></details>
{{template "foot"}}{{end}}

{{define "dir"}}{{template "head"}}
<a class="crumb" href="/">← Categories</a>
<img class="top" src="{{.Dir.Banner}}" alt="">
<h1>{{.Dir.Name}}</h1>
<div class="meta">{{.From}}–{{.To}} of {{.Total}}</div>
<div class="list">{{$id := .ID}}{{range .Dir.Contents.Content}}<a href="/t/{{.Title.ID}}?from={{$id}}">
<img src="{{.Title.Icon}}" alt="" loading="lazy"><div><div>{{.Title.Name}}{{if .Title.New}} <i class="new" style="position:static">New</i>{{end}}</div>
<small>{{.Title.Publisher.Name}} · {{.Title.Genre}} · {{.Title.Date}}</small></div></a>{{end}}</div>
<div class="pager">{{if .Prev}}<a href="?offset={{.Prev}}">← Previous</a>{{else}}{{if eq .From 1}}<span></span>{{else}}<a href="?offset=0">← Previous</a>{{end}}{{end}}
{{if .Next}}<a href="?offset={{.Next}}">Next →</a>{{end}}</div>
<details><summary>directory reply</summary><pre>{{.Raw}}</pre></details>
{{template "foot"}}{{end}}

{{define "title"}}{{template "head"}}
<a class="crumb" href="{{if .Back}}/d/{{.Back}}{{else}}/{{end}}">← Back</a>
<img class="top" src="{{.T.Banner}}" alt="">
<div style="display:flex;gap:12px;align-items:center;margin-bottom:10px">
<img src="{{.T.Icon}}" alt="" style="width:64px;height:64px;object-fit:contain;border-radius:8px;background:#fff">
<div><h1 style="margin:0">{{.T.Name}}</h1><div class="meta">{{.T.Publisher.Name}} · {{.T.Genre}} · {{.T.Date}}</div></div></div>
<p><span class="badge">{{.T.ProductCode}}</span>{{if .T.TitleID}}<span class="badge">{{.T.TitleID}}</span>{{end}}
<span class="badge">{{if .T.Download}}downloadable{{else}}browse only{{end}}</span><span class="badge">price: {{.Status}}</span></p>
<div class="desc">{{.T.Description}}</div>
<p class="meta">{{.T.Disclaimer}}</p>
<details><summary>title reply</summary><pre>{{.Raw}}</pre></details>
<details><summary>online_prices reply</summary><pre>{{.RawPrice}}</pre></details>
{{template "foot"}}{{end}}
`))
