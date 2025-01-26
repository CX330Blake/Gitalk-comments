# Deployer

This site is deploy on GitHub.

# 魔改

Modify `util.js`

```javascript
// 获取自定义播放列表
  getCustomPlayList: function () {
    if (!window.location.pathname.startsWith("/music/")) {
      return;
    }
    const urlParams = new URLSearchParams(window.location.search);
    const userId = "7032963191";
    const userServer = "netease";
    const anMusicPageMeting = document.getElementById("anMusic-page-meting");
    if (urlParams.get("id") && urlParams.get("server")) {
      const id = urlParams.get("id");
      const server = urlParams.get("server");
      anMusicPageMeting.innerHTML = `<meting-js id="${id}" server=${server} type="playlist" type="playlist" mutex="true" preload="auto" theme="var(--anzhiyu-main)" order="list" list-max-height="calc(100vh - 169px)!important"></meting-js>`;
    } else {
      anMusicPageMeting.innerHTML = `<meting-js id="${userId}" server="${userServer}" type="playlist" mutex="true" preload="auto" theme="var(--anzhiyu-main)" order="list" list-max-height="calc(100vh - 169px)!important"></meting-js>`;
    }
    anzhiyu.changeMusicBg(false);
  },
```

music.styl 添加以下

```stylus
// 音樂界面隱藏一些音樂按鈕
#anMusic-page
  #anMusicRefreshBtn, #anMusicBtnGetSong, #anMusicSwitching
    display none
```

並且把 aplayer-icon-loop、aplayer-icon-order、aplayer-volume-wrap 設為不可見

```stylus
&.aplayer-icon-loop, &.aplayer-icon-order
  display none
  margin-right 15px
```

```stylus
.aplayer-volume-wrap
  display none
  .aplayer-volume-bar-wrap
    bottom: 0;
    right: -5px;
```

highlight.styl 修改如下

```stylus
&.expand-done
  i.anzhiyufont.anzhiyu-icon-angle-double-down
    transform: rotate(180deg)
    transition: all 0s, background 0.3s
```

sidebar.styl 新增以下

```stylus
.fa, .fa-solid, .fab, .far, .fas
  line-height inherit !important // 或者您想要设置的其他值
```

code.css 修改如下（背景色和字體顏色在 yml 改）

```css
#article-container code {
    /* padding: 0.2rem 0.4rem; */
    border-radius: 4px;
    /* margin: 0 4px; */
    line-height: 2;
    /* color: var(--anzhiyu-theme); 更改行內代碼樣式 */
    /* box-shadow: var(--anzhiyu-shadow-border); */
}
```

en.yml 修改如下

```yaml
sticky: Pinned
```

card_webinfo.pug 修改如下

```pug
if theme.aside.card_webinfo.enable
  .card-webinfo
    .item-headline
      i.anzhiyufont.anzhiyu-icon-chart-line
      span= _p('aside.card_webinfo.headline')
    .webinfo
      if theme.aside.card_webinfo.post_count
        .webinfo-item
          .webinfo-item-title
            i.fa-solid.fa-file-lines
            .item-name= _p('aside.card_webinfo.article_name') + " :"
          .item-count= site.posts.length
      if theme.runtimeshow.enable
        .webinfo-item
          .webinfo-item-title
            i.fa-solid.fa-stopwatch
            .item-name= _p('aside.card_webinfo.runtime.name') + " :"
          .item-count#runtimeshow(data-publishDate=date_xml(theme.runtimeshow.publish_date))
            i.anzhiyufont.anzhiyu-icon-spinner.anzhiyu-spin
      if theme.wordcount.enable && theme.wordcount.total_wordcount
        .webinfo-item
          .webinfo-item-title
            i.fa-solid.fa-font
            .item-name=_p('aside.card_webinfo.site_wordcount') + " :"
          .item-count=totalcount(site)
      if theme.busuanzi.site_uv
        .webinfo-item
          .webinfo-item-title
            i.fa-solid.fa-universal-access
            .item-name= _p('aside.card_webinfo.site_uv_name') + " :"
          .item-count#busuanzi_value_site_uv
            i.anzhiyufont.anzhiyu-icon-spinner.anzhiyu-spin
      if theme.busuanzi.site_pv
        .webinfo-item
          .webinfo-item-title
            i.fa-solid.fa-square-poll-vertical
            .item-name= _p('aside.card_webinfo.site_pv_name') + " :"
          .item-count#busuanzi_value_site_pv
            i.anzhiyufont.anzhiyu-icon-spinner.anzhiyu-spin
      if theme.aside.card_webinfo.last_push_date
        .webinfo-item
          .webinfo-item-title
            i.fa-solid.fa-hourglass-start
            .item-name= _p('aside.card_webinfo.last_push_date.name') + " :"
          .item-count#last-push-date(data-lastPushDate=date_xml(Date.now()))
            i.anzhiyufont.anzhiyu-icon-spinner.anzhiyu-spin
```

nav.styl 修改如下

```stylus
.back-home-button
  display none
  width 35px
  height 35px
  padding 0 !important
  align-items center
  justify-content center
  margin-right 4px
  transition 0.3s
  border-radius 8px
  @media (min-width: 770px)
    display flex
```

main.js 修改如下

```javascript
if (willChangeMode === "dark") {
    activateDarkMode();
    // GLOBAL_CONFIG.Snackbar !== undefined &&
    //     anzhiyu.snackbarShow(GLOBAL_CONFIG.Snackbar.day_to_night);
} else {
    activateLightMode();
    // GLOBAL_CONFIG.Snackbar !== undefined &&
    //     anzhiyu.snackbarShow(GLOBAL_CONFIG.Snackbar.night_to_day);
}
```

sidebar.styl 修改如下

```stylus
#aside-content #card-toc span.toc-number {
  display: inline;
}
```

index.styl 新增如下

```stylus
#catalog-list
    overflow hidden
    scrollbar-width none /* Firefox 特有 */

    &::-webkit-scrollbar
        display none /* 完全隱藏滾動條 */
```

aside.styl 修改如下

```stylus
.toc-content
      overflow-y: scroll
      overflow-y: overlay
      margin: 0 -24px
      max-height: calc(100vh - 200px)
      width: calc(100% + 48px)
```

\_config.yml 新增以下

```yml
search:
    path: search.xml
    field: post
    content: true # 文章内容
    template: source/_data/search.xml # 自定义模板
```

新增 source/\_data/search.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<search>
  {% if posts %}
  {% for post in posts.toArray() %}
    {% if post.indexing == undefined or post.indexing %}
    <entry>
      <title>{{ post.title }}</title>
      <link href="{{ (url + post.path) | uriencode }}"/>
      <url>{{ (url + post.path) | uriencode }}</url>
      <cover>{{ post.cover }}</cover>
      <date>{{ post.date }}</date>
      {% if content %}
        <content type="html"><![CDATA[{{ post.content | noControlChars | safe }}]]></content>
      {% endif %}
      {% if post.categories and post.categories.length>0 %}
      <categories>
          {% for cate in post.categories.toArray() %}
          <category> {{ cate.name }} </category>
          {% endfor %}
      </categories>
      {% endif %}
      {% if post.tags and post.tags.length>0 %}
        <tags>
            {% for tag in post.tags.toArray() %}
            <tag> {{ tag.name }} </tag>
            {% endfor %}
        </tags>
      {% endif %}
    </entry>
    {% endif %}
    {% endfor %}
  {% endif %}
  {% if pages %}
    {% for page in pages.toArray() %}
    {% if post.indexing == undefined or post.indexing %}
    <entry>
      <title>{{ page.title }}</title>
      <link href="{{ (url + page.path) | uriencode }}"/>
      <url>{{ (url + page.path) | uriencode }}</url>
      <cover>{{ post.cover }}</cover>
      <date>{{ post.date }}</date>
      {% if content %}
        <content type="html"><![CDATA[{{ page.content | noControlChars | safe }}]]></content>
      {% endif %}
    </entry>
    {% endif %}
    {% endfor %}
  {% endif %}
</search>
```

local-search.js 修改為（新增封面以及修復其他問題）

```javascript
window.addEventListener("load", () => {
    let loadFlag = false;
    let dataObj = [];
    const $searchMask = document.getElementById("search-mask");

    function capitalizeFirstLetter(str) {
        if (!str) return str; // 確保字串不為空

        // 輔助函數：將單詞的首字母大寫
        const capitalize = (word) => {
            if (!word) return word; // 確保單詞不為空
            return word.charAt(0).toUpperCase() + word.slice(1);
        };

        // 將字串拆分為單詞，對每個單詞進行首字母大寫，然後重新組合
        let temp = str.split(" ");
        temp.forEach((item, index) => {
            temp[index] = capitalize(item);
        });

        return temp.join(" "); // 返回首字母大寫後的字串
    }

    const openSearch = () => {
        const bodyStyle = document.body.style;
        bodyStyle.width = "100%";
        bodyStyle.overflow = "hidden";
        anzhiyu.animateIn($searchMask, "to_show 0.5s");
        anzhiyu.animateIn(
            document.querySelector("#local-search .search-dialog"),
            "titleScale 0.5s"
        );
        setTimeout(() => {
            document.querySelector("#local-search-input input").focus();
        }, 100);
        if (!loadFlag) {
            search();
            loadFlag = true;
        }
        // shortcut: ESC
        document.addEventListener("keydown", function f(event) {
            if (event.code === "Escape") {
                closeSearch();
                document.removeEventListener("keydown", f);
            }
        });
    };

    const closeSearch = () => {
        const bodyStyle = document.body.style;
        bodyStyle.width = "";
        bodyStyle.overflow = "";
        anzhiyu.animateOut(
            document.querySelector("#local-search .search-dialog"),
            "search_close .5s"
        );
        anzhiyu.animateOut($searchMask, "to_hide 0.5s");
    };

    const searchClickFn = () => {
        document
            .querySelector("#search-button > .search")
            .addEventListener("click", openSearch);
        document
            .querySelector("#menu-search")
            .addEventListener("click", openSearch);
    };

    const searchClickFnOnce = () => {
        document
            .querySelector("#local-search .search-close-button")
            .addEventListener("click", closeSearch);
        $searchMask.addEventListener("click", closeSearch);
        if (GLOBAL_CONFIG.localSearch.preload)
            dataObj = fetchData(GLOBAL_CONFIG.localSearch.path);
    };

    // check url is json or not
    const isJson = (url) => {
        const reg = /\.json$/;
        return reg.test(url);
    };

    const fetchData = async (path) => {
        let data = [];
        const response = await fetch(path);
        if (isJson(path)) {
            data = await response.json();
        } else {
            const res = await response.text();
            const t = await new window.DOMParser().parseFromString(
                res,
                "text/xml"
            );
            const a = await t;

            data = [...a.querySelectorAll("entry")].map((item) => {
                let tagsArr = [];
                if (
                    item.querySelector("tags") &&
                    item.querySelector("tags").getElementsByTagName("tag")
                ) {
                    Array.prototype.forEach.call(
                        item.querySelector("tags").getElementsByTagName("tag"),
                        function (item, index) {
                            tagsArr.push(item.textContent);
                        }
                    );
                }
                let content =
                    item.querySelector("content") &&
                    item.querySelector("content").textContent;
                let imgReg = /<img.*?(?:>|\/>)/gi; //匹配圖片中的img標籤
                let srcReg = /src=[\'\"]?([^\'\"]*)[\'\"]?/i; // 匹配圖片中的src
                let arr = content.match(imgReg); //篩選出所有的img
                let cover =
                    item.querySelector("cover") &&
                    item.querySelector("cover").textContent;
                let srcArr = [];
                if (arr) {
                    for (let i = 0; i < arr.length; i++) {
                        let src = arr[i].match(srcReg);
                        // 獲取圖片地址
                        if (!src[1].indexOf("http")) srcArr.push(src[1]);
                    }
                }

                return {
                    title: item.querySelector("title").textContent,
                    content: content,
                    url: item.querySelector("url").textContent,
                    tags: tagsArr,
                    // oneImage: srcArr && srcArr[0],
                    oneImage: cover,
                };
            });
        }
        if (response.ok) {
            const $loadDataItem = document.getElementById("loading-database");
            $loadDataItem.nextElementSibling.style.display = "block";
            $loadDataItem.remove();
        }
        return data;
    };

    const search = () => {
        if (!GLOBAL_CONFIG.localSearch.preload) {
            dataObj = fetchData(GLOBAL_CONFIG.localSearch.path);
        }
        const $input = document.querySelector("#local-search-input input");
        const $resultContent = document.getElementById("local-search-results");
        const $loadingStatus = document.getElementById("loading-status");

        $input.addEventListener("input", function () {
            const keywords = this.value.trim().toLowerCase().split(/[\s]+/);
            if (keywords[0] !== "")
                $loadingStatus.innerHTML =
                    '<i class="anzhiyufont anzhiyu-icon-spinner anzhiyu-pulse-icon"></i>';

            $resultContent.innerHTML = "";
            let str = '<div class="search-result-list">';
            if (keywords.length <= 0) return;
            let count = 0;
            // perform local searching
            dataObj.then((data) => {
                data.forEach((data) => {
                    let isMatch = true;
                    let dataTitle = data.title ? data.title.trim() : "";
                    let dataTitleForSearch = data.title
                        ? data.title.trim().toLowerCase()
                        : "";
                    let dataTags = data.tags;
                    let oneImage = data.oneImage ?? "";
                    const dataContent = data.content
                        ? data.content
                              .trim()
                              .replace(/<[^>]+>/g, "")
                              .toLowerCase()
                        : "";
                    const dataUrl = data.url.startsWith("/")
                        ? data.url
                        : GLOBAL_CONFIG.root + data.url;
                    let indexTitle = -1;
                    let indexContent = -1;
                    let firstOccur = -1;
                    // only match articles with not empty titles and contents
                    if (dataTitleForSearch !== "" || dataContent !== "") {
                        keywords.forEach((keyword, i) => {
                            indexTitle = dataTitleForSearch.indexOf(keyword);
                            indexContent = dataContent.indexOf(keyword);
                            if (indexTitle < 0 && indexContent < 0) {
                                isMatch = false;
                            } else {
                                if (indexContent < 0) {
                                    indexContent = 0;
                                }
                                if (i === 0) {
                                    firstOccur = indexContent;
                                }
                            }
                        });
                    } else {
                        isMatch = false;
                    }

                    // show search results
                    if (isMatch) {
                        if (firstOccur >= 0) {
                            // cut out 130 characters
                            // let start = firstOccur - 30 < 0 ? 0 : firstOccur - 30
                            // let end = firstOccur + 50 > dataContent.length ? dataContent.length : firstOccur + 50
                            let start = firstOccur - 30;
                            let end = firstOccur + 100;
                            let pre = "";
                            let post = "";

                            if (start < 0) {
                                start = 0;
                            }

                            if (start === 0) {
                                end = 100;
                            } else {
                                pre = "...";
                            }

                            if (end > dataContent.length) {
                                end = dataContent.length;
                            } else {
                                post = "...";
                            }

                            let matchContent = dataContent.substring(
                                start,
                                end
                            );

                            // highlight all keywords
                            keywords.forEach((keyword) => {
                                const regS = new RegExp(keyword, "gi");
                                matchContent = matchContent.replace(
                                    regS,
                                    '<span class="search-keyword">' +
                                        keyword +
                                        "</span>"
                                );
                                dataTitle = dataTitle.replace(
                                    regS,
                                    '<span class="search-keyword">' +
                                        capitalizeFirstLetter(keyword) +
                                        "</span>"
                                );
                            });

                            str += '<div class="local-search__hit-item">';
                            if (oneImage) {
                                str += `<div class="search-left"><a href='${dataUrl}'"><img src="${oneImage}" data-fancybox='gallery'></a>`;
                            } else {
                                str +=
                                    '<div class="search-left" style="width:0">';
                            }

                            str += "</div>";

                            if (oneImage) {
                                str +=
                                    '<div class="search-right"><a href="' +
                                    dataUrl +
                                    '" class="search-result-title">' +
                                    dataTitle +
                                    "</a>";
                            } else {
                                str +=
                                    '<div class="search-right" style="width: 100%"><a href="' +
                                    dataUrl +
                                    '" class="search-result-title">' +
                                    dataTitle +
                                    "</a>";
                            }

                            count += 1;

                            if (dataContent !== "") {
                                str +=
                                    '<p class="search-result" onclick="pjax.loadUrl(`' +
                                    dataUrl +
                                    '`)">' +
                                    pre +
                                    matchContent +
                                    post +
                                    "</p>";
                            }
                            if (dataTags.length) {
                                str += '<div class="search-result-tags">';

                                for (let i = 0; i < dataTags.length; i++) {
                                    const element = dataTags[i].trim();

                                    str +=
                                        '<a class="tag-list" href="/tags/' +
                                        element +
                                        '/" data-pjax-state="" one-link-mark="yes">#' +
                                        element +
                                        "</a>";
                                }

                                str += "</div>";
                            }
                        }
                        str += "</div></div>";
                    }
                });
                if (count === 0) {
                    str +=
                        '<div id="local-search__hits-empty">' +
                        GLOBAL_CONFIG.localSearch.languages.hits_empty.replace(
                            /\$\{query}/,
                            this.value.trim()
                        ) +
                        "</div>";
                }
                str += "</div>";
                $resultContent.innerHTML = str;
                if (keywords[0] !== "") $loadingStatus.innerHTML = "";
                window.pjax && window.pjax.refresh($resultContent);
            });
        });
    };

    searchClickFn();
    searchClickFnOnce();

    // pjax
    window.addEventListener("pjax:complete", () => {
        !anzhiyu.isHidden($searchMask) && closeSearch();
        searchClickFn();
    });
});
```

local_search.css 替換為

```css
#local-search .search-dialog .local-search__hit-item:before {
    content: none !important;
}

#local-search .search-dialog .local-search__hit-item {
    padding: 10px !important;
    border-radius: 8px;
    border: var(--style-border);
    margin-bottom: 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

#local-search .search-dialog .local-search__hit-item .search-left {
    width: 35%;
    padding: 1rem;
}

#local-search .search-dialog .local-search__hit-item .search-right {
    width: 60%;
}

#local-search .search-dialog .local-search__hit-item .search-left img {
    object-fit: cover;
    width: 100%;
    background: var(--anzhiyu-secondbg);
    border-radius: 8px;
    transition: all 0.6s ease 0s;
}

#local-search .search-dialog .local-search__hit-item .search-left:hover img {
    filter: brightness(0.82) !important;
    transform: scale(1.06) !important;
    transition: 0.3s ease-in-out;
}

#local-search .search-dialog .local-search__hit-item .search-result {
    cursor: pointer;
}

#local-search .tag-list {
    padding: 4px 8px;
    border-radius: 8px;
    margin-right: 0.5rem;
    margin-top: 0.5rem;
    border: var(--style-border);
    cursor: pointer;
}

#local-search .search-dialog .local-search__hit-item .tag-list {
    display: inline;
}

#local-search .search-dialog .local-search__hit-item .tag-list:hover {
    background: var(--anzhiyu-main);
    color: var(--anzhiyu-white);
}

#local-search .search-dialog .search-right .search-result-tags {
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-start;
}

@media screen and (max-width: 768px) {
    #local-search .search-dialog .local-search__hit-item .search-right {
        width: 100%;
        padding: 0.8rem;
    }

    #local-search .search-dialog .local-search__hit-item .search-left {
        display: none;
    }
}
```

themes/my-anzhiyu/source/css/\_search/index.styl 修改如下

```diff
- .search-dialog
-   position: fixed
-   top: 5rem
-   left: 50%
-   z-index: 1001
-   display: none
-   margin-left: -18.75rem;
-   padding: 1.25rem;
-   width: 37.5rem;
-   border-radius: 8px
-   background: var(--search-bg)
-   border-radius: 12px;
-   box-shadow: var(--anzhiyu-shadow-lightblack);
-   background: var(--anzhiyu-card-bg);
-   border: var(--style-border);
-   transition: .3s;
+ .search-dialog
+   position: fixed
+   top: 5rem
+   left: 0
+   right: 0
+   z-index: 1001
+   display: none
+   // margin-left: -18.75rem;
+   margin: auto;
+   padding: 1.25rem;
+   max-width: 70rem;
+   width: 100%;
+   border-radius: 8px
+   background: var(--search-bg)
+   border-radius: 12px;
+   box-shadow: var(--anzhiyu-shadow-lightblack);
+   background: var(--anzhiyu-card-bg);
+   border: var(--style-border);
+   transition: .3s;
```

prismjs/diff.styl 修改如下

```stylus
if $highlight_theme == 'darker' || ($highlight_theme == 'mac')
  // prism-atom-dark
  /*
  pre[class*='language-']
    .token.comment,
    .token.prolog,
    .token.doctype,
    .token.cdata
      color: #7C7C7C

    .token.punctuation
      color: #c5c8c6

    .namespace
      opacity: .7

    .token.property,
    .token.keyword,
    .token.tag
      color: #96CBFE

    .token.class-name
      color: #FFFFB6

    .token.boolean,
    .token.constant
      color: #99CC99

    .token.symbol,
    .token.deleted
      color: #f92672

    .token.number
      color: #FF73FD

    .token.selector,
    .token.attr-name,
    .token.string,
    .token.char,
    .token.builtin,
    .token.inserted
      color: #A8FF60

    .token.variable
      color: #C6C5FE

    .token.operator
      color: #EDEDED

    .token.entity
      color: #FFFFB6
      cursor: help

    .token.url
      color: #96CBFE

    .language-css .token.string,
    .style .token.string
      color: #87C38A

    .token.atrule,
    .token.attr-value
      color: #F9EE98

    .token.function
      color: #DAD085

    .token.regex
      color: #E9C062

    .token.important
      color: #fd971f

    .token.important,
    .token.bold
      font-weight: bold

    .token.italic
      font-style: italic
      */

      // prism-dracula
  pre[class*='language-']
    .token.comment,
    .token.prolog,
    .token.doctype,
    .token.cdata
      color: #6272a4

    .token.punctuation
      color: #f8f8f2

    .namespace
      opacity: .7

    .token.property,
    .token.tag,
    .token.constant,
    .token.symbol,
    .token.deleted
      color: #ff79c6

    .token.boolean,
    .token.number
      color: #bd93f9

    .token.selector,
    .token.attr-name,
    .token.string,
    .token.char,
    .token.builtin,
    .token.inserted
      color: #50fa7b

    .token.operator,
    .token.entity,
    .token.url,
    .language-css .token.string,
    .style .token.string,
    .token.variable
      color: #f8f8f2

    .token.atrule,
    .token.attr-value,
    .token.function,
    .token.class-name
      color: #f1fa8c

    .token.keyword
      color: #8be9fd

    .token.regex,
    .token.important
      color: #ffb86c

    .token.important,
    .token.bold
      font-weight: bold

    .token.italic
      font-style: italic

    .token.entity
      cursor: help
```

index.styl 的 Dark mode 修改如下

```stylus
  --anzhiyu-lighttext: #BD93F9;
```

line-numbers.styl 修改如下

```stylus
#article-container
  pre[class*='language-']
    &.line-numbers
      position: relative
      padding-left: 3.8em
      padding-right: 3.8em
      counter-reset: linenumber
      line-height: $line-height-code-block
```

my-anzhiyu/source/css/\_highlight/prismjs/index.styl 修改如下

```stylus
if $prismjs_line_number
  @require 'line-number'

if $highlight_theme != false
  @require 'diff'

#article-container
  pre[class*='language-']
    scrollbar-color: var(--hlscrollbar-bg) transparent

    &::-webkit-scrollbar-thumb
      background: var(--hlscrollbar-bg)

    &:not(.line-numbers)
      padding: 10px 20px

    .caption
      margin-left: -3.8em
      padding: 4px 16px !important

      a
        padding: 0 !important

    /*
    *:first-child
      margin-left: -1px;
    */
```

# hexo-butterfly-envelope

`main.js`中把中文改為英文

# 魔改資源

-   [文章主色调(插件)](https://www.naokuo.top/p/fb2f8d77.html)
-   [为主页文章卡片添加擦亮动画效果](https://blog.kouseki.cn/posts/dda6.html)
-   [重构记录 - 4](https://meuicat.com/blog/42/)
-   [好看的昼夜切换按钮](https://www.naokuo.top/p/1c3b759a.html)

# 安裝 hexo-all-minifier

```bash
npm install hexo-all-minifier --save
```
