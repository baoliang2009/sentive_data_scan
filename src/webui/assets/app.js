/* DataSentinel 本地控制台 —— 无框架前端 */
(function () {
  'use strict';

  var CONF = window.__SENTINEL__ || { token: '', version: '', platform: '' };
  var SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  var SEV_LABEL = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' };
  var SEV_COLOR = {
    critical: '#d92d20',
    high: '#f04438',
    medium: '#f79009',
    low: '#4e7ddc',
    info: '#98a2b3'
  };
  var ACK_LABEL = { open: '未确认', acked: '已确认', all: '全部' };

  var ICON = {
    search:
      '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.4-3.4"/></svg>',
    folder:
      '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7.5A1.5 1.5 0 014.5 6h4l2 2.5h7A1.5 1.5 0 0119 10v7a1.5 1.5 0 01-1.5 1.5h-13A1.5 1.5 0 013 17V7.5z"/></svg>',
    close:
      '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>',
    copy:
      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 012-2h8"/></svg>',
    shield:
      '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7.5 3v5.6c0 4.3-3.1 8-7.5 9.4-4.4-1.4-7.5-5.1-7.5-9.4V6L12 3z"/><circle cx="12" cy="11.4" r="2.2"/></svg>',
    empty:
      '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16v12H4z"/><path d="M4 11h16"/><path d="M8 7V5h8v2"/></svg>',
    up:
      '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5"/><path d="M6 11l6-6 6 6"/></svg>'
  };

  var state = {
    route: '',
    overview: null,
    recent: [],
    findings: {
      items: [],
      counts: {},
      total: 0,
      limit: 100,
      hasMore: false,
      filters: { severity: 'all', ack: 'open', category: 'all', q: '' },
      selected: {},
      selectedCount: 0,
      loading: false
    },
    rules: null,
    ruleQuery: '',
    ruleCategory: 'all',
    settings: null,
    draftRoots: null,
    scanDraft: null,
    scan: { running: false },
    poll: null,
    modalStack: []
  };

  /* ------------------------------------------------------------- helpers */

  function $(selector, root) {
    return (root || document).querySelector(selector);
  }
  function $$(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }
  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
  function attr(value) {
    return esc(value);
  }
  function num(value) {
    var n = Number(value || 0);
    return n.toLocaleString('zh-CN');
  }
  function pct(part, total) {
    if (!total) return '0%';
    return ((part / total) * 100).toFixed(part / total < 0.1 ? 1 : 0) + '%';
  }
  function sevChip(sev, text) {
    return '<span class="sev sev-' + attr(sev) + '">' + esc(text || SEV_LABEL[sev] || sev) + '</span>';
  }
  function sevTotal(counts) {
    return SEV_ORDER.reduce(function (acc, key) {
      return acc + Number(counts[key] || 0);
    }, 0);
  }
  function debounce(fn, wait) {
    var timer = null;
    return function () {
      var args = arguments;
      var self = this;
      clearTimeout(timer);
      timer = setTimeout(function () {
        fn.apply(self, args);
      }, wait);
    };
  }

  function api(path, options) {
    options = options || {};
    var headers = { 'X-Sentinel-Token': CONF.token };
    if (options.body) headers['Content-Type'] = 'application/json';
    return fetch(path, {
      method: options.method || 'GET',
      headers: headers,
      body: options.body ? JSON.stringify(options.body) : undefined
    }).then(function (response) {
      return response
        .json()
        .catch(function () {
          return {};
        })
        .then(function (data) {
          if (!response.ok) {
            var error = new Error(data.error || '请求失败（' + response.status + '）');
            error.status = response.status;
            throw error;
          }
          return data;
        });
    });
  }

  function toast(message, options) {
    options = options || {};
    var root = $('#toast-root');
    var el = document.createElement('div');
    el.className = 'toast' + (options.type === 'error' ? ' error' : '');
    el.innerHTML = '<span>' + esc(message) + '</span>';
    if (options.action) {
      var button = document.createElement('button');
      button.textContent = options.action.label;
      button.addEventListener('click', function () {
        options.action.onClick();
        el.remove();
      });
      el.appendChild(button);
    }
    root.appendChild(el);
    setTimeout(function () {
      el.remove();
    }, options.duration || 3600);
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        function () {
          toast('已复制到剪贴板');
        },
        function () {
          fallbackCopy(text);
        }
      );
      return;
    }
    fallbackCopy(text);
  }
  function fallbackCopy(text) {
    var area = document.createElement('textarea');
    area.value = text;
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    try {
      document.execCommand('copy');
      toast('已复制到剪贴板');
    } catch (error) {
      toast('复制失败，请手动选择文本', { type: 'error' });
    }
    area.remove();
  }

  /* --------------------------------------------------------------- modal */

  function pushModal(html) {
    state.modalStack.push(html);
    renderModal();
  }
  function replaceModal(html) {
    if (!state.modalStack.length) {
      state.modalStack.push(html);
    } else {
      state.modalStack[state.modalStack.length - 1] = html;
    }
    renderModal();
  }
  function popModal() {
    state.modalStack.pop();
    renderModal();
  }
  function closeAllModals() {
    state.modalStack = [];
    renderModal();
  }
  function renderModal() {
    var root = $('#modal-root');
    if (!state.modalStack.length) {
      root.innerHTML = '';
      return;
    }
    var top = state.modalStack[state.modalStack.length - 1];
    root.innerHTML =
      '<div class="modal-backdrop" data-action="modal-backdrop">' + top + '</div>';
  }

  /* -------------------------------------------------------------- drawer */

  function openFinding(item) {
    var drawer = $('#drawer');
    var ackButton = item.acknowledged
      ? '<span class="btn" style="pointer-events:none;opacity:.6">已确认</span>'
      : '<button class="btn btn-primary" data-action="ack-finding" data-id="' + item.id + '">标记为已确认</button>';
    drawer.innerHTML =
      '<div class="drawer-head">' +
      sevChip(item.severity) +
      '<span class="small muted">' +
      esc(item.category_label || item.category) +
      '</span>' +
      '<span class="spacer"></span>' +
      '<button class="icon-btn" data-action="close-drawer" title="关闭">' +
      ICON.close +
      '</button>' +
      '</div>' +
      '<div class="drawer-body">' +
      '<h2>' +
      esc(item.rule_name) +
      '</h2>' +
      '<div class="field"><div class="field-label">脱敏值</div>' +
      '<div class="masked-value">' +
      esc(item.masked) +
      '<button class="icon-btn" data-action="copy" data-text="' +
      attr(item.masked) +
      '" title="复制">' +
      ICON.copy +
      '</button></div></div>' +
      '<div class="field"><div class="field-label">文件位置</div>' +
      '<div class="field-value mono">' +
      esc(item.path) +
      ' <span class="muted">第 ' +
      item.line +
      ' 行</span></div></div>' +
      '<div class="field"><div class="field-label">上下文</div><pre class="snippet">' +
      esc(item.snippet || '（无上下文）') +
      '</pre></div>' +
      '<div class="field"><div class="field-label">规则</div><div class="field-value">' +
      esc(item.rule_id) +
      ' · ' +
      esc(item.category_label || item.category) +
      '</div></div>' +
      '<div class="field"><div class="field-label">检测时间</div><div class="field-value">' +
      esc(item.detected_at_text) +
      '</div></div>' +
      '<div class="field"><div class="field-label">状态</div><div class="field-value">' +
      (item.acknowledged ? '已确认（不再重复提醒）' : '未确认') +
      '</div></div>' +
      '<div class="hint-line">默认不保存命中原文，仅记录脱敏值、上下文片段与哈希，用于去重与追溯。</div>' +
      '</div>' +
      '<div class="drawer-foot">' +
      ackButton +
      '<button class="btn" data-action="reveal" data-path="' + attr(item.path) + '">在文件夹中显示</button>' +
      '<button class="btn" data-action="copy" data-text="' + attr(item.path) + '">复制路径</button>' +
      '</div>';
    document.body.classList.add('drawer-open');
    $('#drawer').setAttribute('aria-hidden', 'false');
  }

  function closeDrawer() {
    document.body.classList.remove('drawer-open');
    $('#drawer').setAttribute('aria-hidden', 'true');
  }

  /* ------------------------------------------------------------- overview */

  var ROUTES = {
    overview: { title: '概览', sub: '本机敏感数据扫描与落盘监控', load: loadOverview },
    findings: { title: '命中记录', sub: '检测结果仅以脱敏形式保存在本机数据库', load: loadFindingsView },
    rules: { title: '检测规则', sub: '内置规则可按需关闭，也可在配置文件中添加自定义规则', load: loadRulesView },
    settings: { title: '设置', sub: '扫描范围、通知方式、存储策略与开机自启', load: loadSettingsView }
  };

  function currentRoute() {
    var hash = (location.hash || '#/overview').replace(/^#\/?/, '');
    return ROUTES[hash] ? hash : 'overview';
  }

  function renderRoute() {
    var route = currentRoute();
    state.route = route;
    $$('.nav-item').forEach(function (item) {
      item.classList.toggle('active', item.dataset.route === route);
    });
    $('#page-title').textContent = ROUTES[route].title;
    $('#page-sub').textContent = ROUTES[route].sub;
    closeDrawer();
    closeAllModals();
    $('#view').innerHTML = skeletonHtml();
    ROUTES[route].load().catch(showError);
  }

  function refreshCurrentRoute() {
    var route = currentRoute();
    if (!ROUTES[route]) return;
    ROUTES[route].load().catch(function () {});
  }

  function showError(error) {
    $('#view').innerHTML =
      '<div class="card"><div class="empty">' +
      '<div class="empty-icon">!</div>' +
      '<h3>出错了</h3><p>' +
      esc(error && error.message ? error.message : String(error)) +
      '</p><button class="btn" data-action="reload">重新加载</button></div></div>';
  }

  function skeletonHtml() {
    var stats = '';
    for (var i = 0; i < 4; i += 1) {
      stats +=
        '<div class="stat"><div class="skeleton" style="width:55%"></div>' +
        '<div class="skeleton" style="width:38%;height:26px;margin-top:12px"></div>' +
        '<div class="skeleton" style="width:68%;margin-top:10px"></div></div>';
    }
    return (
      '<div class="stack"><div class="stat-grid">' +
      stats +
      '</div><div class="card"><div class="loading-block">' +
      '<div class="skeleton" style="width:26%"></div>' +
      '<div class="skeleton" style="width:100%"></div>' +
      '<div class="skeleton" style="width:92%"></div>' +
      '<div class="skeleton" style="width:96%"></div>' +
      '</div></div></div>'
    );
  }

  function loadOverview() {
    return Promise.all([api('/api/overview'), api('/api/findings?limit=6&ack=all')]).then(function (
      results
    ) {
      state.overview = results[0];
      state.recent = results[1].items || [];
      updateTopbar();
      renderScanBanner();
      $('#view').innerHTML = overviewHtml();
      if (state.overview.scan && state.overview.scan.running) startPolling();
    });
  }

  function updateTopbar() {
    var overview = state.overview;
    if (!overview) return;
    var watch = $('#chip-watch');
    var autostart = $('#chip-autostart');
    watch.className = 'chip ' + (overview.watch.enabled ? 'on' : 'off');
    watch.querySelector('span:last-child').textContent = overview.watch.enabled
      ? '落盘监控已启用'
      : '落盘监控已关闭';
    watch.title = overview.watch.enabled
      ? '守护进程（sentinel daemon）运行时实时监听文件落盘'
      : '可在配置中开启 watch.enabled';
    autostart.className = 'chip ' + (overview.autostart.installed ? 'on' : 'off');
    autostart.querySelector('span:last-child').textContent = overview.autostart.installed
      ? '开机自启已安装'
      : '开机自启未安装';
    autostart.title = overview.autostart.detail || '';

    var badge = $('#nav-count');
    var count = Number(overview.stats.unacknowledged || 0);
    if (count > 0) {
      badge.hidden = false;
      badge.textContent = count > 99 ? '99+' : String(count);
    } else {
      badge.hidden = true;
    }
  }

  function overviewHtml() {
    var overview = state.overview;
    var stats = overview.stats;
    var counts = stats.by_severity || {};
    var total = sevTotal(counts) || Number(stats.findings || 0);
    var urgent = Number(counts.critical || 0) + Number(counts.high || 0);
    var neverScanned = !stats.last_scan && Number(stats.files || 0) === 0;

    var html = '<div class="stack">';

    html +=
      '<section class="stat-grid">' +
      statCard('未确认命中', num(stats.unacknowledged), '共 ' + num(stats.findings) + ' 处历史命中', Number(stats.unacknowledged) > 0) +
      statCard('严重 / 高危', num(urgent), '需要优先处理', urgent > 0) +
      statCard('扫描台账文件', num(stats.files), '已纳入增量台账') +
      statCard('最近扫描', stats.last_scan_text || '尚无', stats.last_scan ? '按 size + mtime 增量对账' : '还没有执行过扫描', false, true) +
      '</section>';

    if (neverScanned) {
      html +=
        '<section class="hero"><div class="hero-mark">' +
        ICON.shield +
        '</div><div class="hero-main"><h2>开始第一次扫描</h2>' +
        '<p>将扫描以下目录，识别身份证、手机号、银行卡、密码、私钥、云密钥等敏感信息。' +
        '数据不出本机，默认只保存脱敏结果。</p>' +
        '<div class="chips" style="margin-top:10px">' +
        (overview.roots.length
          ? overview.roots
              .map(function (root) {
                return '<span class="path-chip"><span>' + esc(shortPath(root)) + '</span></span>';
              })
              .join('')
          : '<span class="small muted">未找到常用目录，请在设置中手动添加</span>') +
        '</div></div>' +
        '<button class="btn btn-primary" data-action="open-scan">开始扫描</button></section>';
    }

    html +=
      '<div class="split">' +
      severityCard(counts, total) +
      recentCard() +
      '</div>';

    var last = overview.scan && overview.scan.last;
    if (last) html += lastScanCard(last);

    html +=
      '<div class="split">' +
      historyCard(overview.runs) +
      categoryCard(overview.categories, total) +
      '</div>';

    html += '</div>';
    return html;
  }

  function statCard(label, value, foot, alert, small) {
    return (
      '<article class="stat' +
      (alert ? ' alert' : '') +
      '"><div class="stat-label">' +
      esc(label) +
      '</div><div class="stat-value' +
      (small ? ' sm' : '') +
      '">' +
      esc(value) +
      '</div><div class="stat-foot">' +
      esc(foot) +
      '</div></article>'
    );
  }

  function severityCard(counts, total) {
    var bar = '';
    SEV_ORDER.forEach(function (key) {
      var count = Number(counts[key] || 0);
      if (!count || !total) return;
      bar +=
        '<span class="seg-' + key + '" style="width:' + (count / total) * 100 + '%"></span>';
    });
    var legend = SEV_ORDER.map(function (key) {
      var count = Number(counts[key] || 0);
      return (
        '<li><span class="swatch" style="background:' +
        SEV_COLOR[key] +
        '"></span><span class="legend-label">' +
        SEV_LABEL[key] +
        '</span><span class="legend-count">' +
        num(count) +
        '</span><span class="legend-pct">' +
        pct(count, total) +
        '</span></li>'
      );
    }).join('');

    return (
      '<section class="card"><div class="card-head"><h2>严重级别分布</h2>' +
      '<span class="spacer"></span><span class="muted">共 ' +
      num(total) +
      ' 处</span></div>' +
      '<div class="card-body"><div class="sev-bar">' +
      (bar || '') +
      '</div><ul class="legend">' +
      legend +
      '</ul></div></section>'
    );
  }

  function recentCard() {
    var items = state.recent || [];
    var body;
    if (!items.length) {
      body =
        '<div class="empty">' +
        '<div class="empty-icon">' +
        ICON.empty +
        '</div><h3>还没有命中记录</h3>' +
        '<p>扫描完成后，命中的敏感数据会以脱敏形式显示在这里。</p></div>';
    } else {
      body = items
        .map(function (item) {
          return (
            '<div class="hit" data-action="open-finding" data-id="' +
            item.id +
            '">' +
            '<div class="hit-main">' +
            '<div class="hit-title">' +
            sevChip(item.severity) +
            '<span>' +
            esc(item.rule_name) +
            '</span></div>' +
            '<div class="hit-path" title="' +
            attr(item.path) +
            '">' +
            esc(fileName(item.path)) +
            ' <span style="color:var(--text-3)">· ' +
            esc(shortPath(dirName(item.path))) +
            '</span></div>' +
            '<div class="hit-value">' +
            esc(item.masked) +
            '</div></div>' +
            '<div class="hit-time">' +
            esc(item.detected_at_text || '') +
            '</div></div>'
          );
        })
        .join('');
    }
    return (
      '<section class="card"><div class="card-head"><h2>最近命中</h2>' +
      '<span class="spacer"></span><a class="link" href="#/findings">查看全部</a></div>' +
      '<div class="hit-list">' +
      body +
      '</div></section>'
    );
  }

  function lastScanCard(last) {
    var summary = last.summary || {};
    var counts = summary.new_by_severity || {};
    var unchangedOnly =
      Number(summary.files_scanned || 0) === 0 && Number(summary.files_unchanged || 0) > 0;
    var chips = SEV_ORDER.filter(function (key) {
      return Number(counts[key] || 0) > 0;
    })
      .map(function (key) {
        return sevChip(key, SEV_LABEL[key] + ' ' + counts[key]);
      })
      .join(' ');

    return (
      '<section class="card"><div class="card-head"><h2>上次扫描结果</h2>' +
      '<span class="spacer"></span><span class="muted">' +
      esc(last.started_at_text) +
      ' · 用时 ' +
      (last.duration_ms / 1000).toFixed(1) +
      ' s</span></div>' +
      '<div class="card-body">' +
      (unchangedOnly
        ? '<div class="hint-line" style="margin-bottom:12px">本次没有新增或修改的文件，' +
          num(summary.files_unchanged) +
          ' 个文件按 size + mtime 跳过。需要逐文件重新检测请使用「强制全量重扫」。</div>'
        : '') +
      '<div class="stat-grid" style="gap:10px">' +
      statCard('分析文件', num(summary.files_scanned), '未变化 ' + num(summary.files_unchanged) + ' · 跳过 ' + num(summary.files_skipped), false) +
      statCard('命中总数', num(summary.findings), '新增 ' + num(summary.new_findings) + ' 处', false) +
      statCard('排除 / 失败', num(summary.files_excluded) + ' / ' + num(summary.files_failed), '按规则排除，失败通常为权限不足', false) +
      '<article class="stat"><div class="stat-label">本次新增级别</div><div style="margin-top:10px;display:flex;gap:6px;flex-wrap:wrap">' +
      (chips || '<span class="small muted">无新增命中</span>') +
      '</div></article>' +
      '</div></div></section>'
    );
  }

  function historyCard(runs) {
    if (!runs || !runs.length) {
      return (
        '<section class="card"><div class="card-head"><h2>扫描历史</h2></div>' +
        '<div class="empty"><div class="empty-icon">' +
        ICON.empty +
        '</div><h3>暂无扫描记录</h3><p>每次扫描都会写入一条记录，包含分析文件数与新增命中数。</p></div></section>'
      );
    }
    var rows = runs
      .map(function (run) {
        return (
          '<tr><td>' +
          esc(run.started_at_text) +
          '</td><td class="num">' +
          formatSeconds(run.duration_seconds) +
          '</td><td class="num">' +
          num(run.files_scanned) +
          '</td><td class="num">' +
          num(run.findings) +
          '</td><td class="num">' +
          (run.new_findings ? '<strong>+' + num(run.new_findings) + '</strong>' : '0') +
          '</td></tr>'
        );
      })
      .join('');
    return (
      '<section class="card"><div class="card-head"><h2>扫描历史</h2><span class="spacer"></span>' +
      '<span class="muted">最近 ' +
      runs.length +
      ' 次</span></div><div class="table-wrap"><table><thead><tr>' +
      '<th>开始时间</th><th>用时</th><th>分析文件</th><th>命中</th><th>新增</th>' +
      '</tr></thead><tbody>' +
      rows +
      '</tbody></table></div></section>'
    );
  }

  function categoryCard(categories, total) {
    if (!categories || !categories.length) {
      return (
        '<section class="card"><div class="card-head"><h2>分类分布</h2></div>' +
        '<div class="empty"><div class="empty-icon">' +
        ICON.empty +
        '</div><h3>暂无数据</h3><p>完成扫描后可以按数据类型查看命中分布。</p></div></section>'
      );
    }
    var max = categories.reduce(function (acc, item) {
      return Math.max(acc, Number(item.count || 0));
    }, 1);
    var rows = categories
      .map(function (item) {
        var count = Number(item.count || 0);
        return (
          '<li><div class="bars-label"><span>' +
          esc(item.label) +
          '</span><span class="muted">' +
          num(count) +
          ' · ' +
          pct(count, total) +
          '</span></div>' +
          '<div class="bars-track"><div class="bars-fill" style="width:' +
          (count / max) * 100 +
          '%"></div></div></li>'
        );
      })
      .join('');
    return (
      '<section class="card"><div class="card-head"><h2>分类分布</h2></div>' +
      '<div class="card-body"><ul class="bars">' +
      rows +
      '</ul></div></section>'
    );
  }

  function formatSeconds(seconds) {
    var value = Number(seconds || 0);
    if (value < 60) return value + ' s';
    return Math.floor(value / 60) + ' min ' + (value % 60) + ' s';
  }

  function shortPath(path) {
    return String(path || '')
      .replace(/^\/Users\/[^/]+/, '~')
      .replace(/^\/home\/[^/]+/, '~')
      .replace(/^[A-Za-z]:\\Users\\[^\\]+/, '~');
  }

  function fileName(path) {
    var parts = String(path || '').split(/[\\/]/);
    return parts[parts.length - 1] || path;
  }

  function dirName(path) {
    var value = String(path || '');
    var index = Math.max(value.lastIndexOf('/'), value.lastIndexOf('\\'));
    return index > 0 ? value.slice(0, index) : '';
  }

  /* ------------------------------------------------------------- findings */

  function loadFindingsView() {
    var prep = state.overview
      ? Promise.resolve()
      : api('/api/overview').then(function (data) {
          state.overview = data;
          updateTopbar();
        });
    return prep.then(function () {
      renderFindingsPage();
      return refreshFindings();
    });
  }

  function renderFindingsPage() {
    var filters = state.findings.filters;
    var html =
      '<div class="toolbar">' +
      '<div class="search">' +
      ICON.search +
      '<input id="search-input" type="search" placeholder="搜索路径、规则或脱敏值" value="' +
      attr(filters.q) +
      '" autocomplete="off">' +
      '</div>' +
      '<div class="segmented" id="sev-filter">' +
      sevButton('all', '全部') +
      SEV_ORDER.map(function (key) {
        return sevButton(key, SEV_LABEL[key]);
      }).join('') +
      '</div>' +
      '<select class="select" id="ack-filter">' +
      '<option value="open"' +
      (filters.ack === 'open' ? ' selected' : '') +
      '>仅未确认</option>' +
      '<option value="acked"' +
      (filters.ack === 'acked' ? ' selected' : '') +
      '>已确认</option>' +
      '<option value="all"' +
      (filters.ack === 'all' ? ' selected' : '') +
      '>全部状态</option>' +
      '</select>' +
      '<select class="select" id="category-filter"><option value="all">全部类型</option></select>' +
      '<span class="spacer" style="flex:1"></span>' +
      '<button class="btn btn-sm" data-action="export-report">导出报告</button>' +
      '<button class="btn btn-sm btn-danger" data-action="ack-all">全部确认</button>' +
      '</div>' +
      '<div id="selection-slot"></div>' +
      '<section class="card"><div class="table-wrap findings-table-wrap"><table>' +
      '<thead><tr>' +
      '<th style="width:34px"><input type="checkbox" id="select-all" title="全选当前页"></th>' +
      '<th style="width:72px">级别</th><th>规则</th><th>文件</th><th>脱敏值</th>' +
      '<th style="width:168px">检测时间</th><th style="width:76px">状态</th>' +
      '</tr></thead><tbody id="findings-body">' +
      skeletonRows(6) +
      '</tbody></table></div>' +
      '<div class="card-head" id="findings-foot" style="border-bottom:0;border-top:1px solid var(--line)"></div>' +
      '</section>';
    $('#view').innerHTML = html;
    fillCategoryFilter();
  }

  function sevButton(key, label) {
    var active = state.findings.filters.severity === key ? ' active' : '';
    var count = key === 'all' ? '' : '<span class="count">' + num(state.findings.counts[key] || 0) + '</span>';
    return (
      '<button class="' +
      active.trim() +
      '" data-action="set-severity" data-value="' +
      key +
      '">' +
      esc(label) +
      count +
      '</button>'
    );
  }

  function fillCategoryFilter() {
    var select = $('#category-filter');
    if (!select || !state.overview) return;
    var options = ['<option value="all">全部类型</option>'];
    (state.overview.categories || []).forEach(function (item) {
      options.push('<option value="' + attr(item.category) + '">' + esc(item.label) + '</option>');
    });
    select.innerHTML = options.join('');
    select.value = state.findings.filters.category;
  }

  function skeletonRows(count) {
    var rows = '';
    for (var i = 0; i < count; i += 1) {
      rows +=
        '<tr><td></td><td><div class="skeleton" style="width:40px"></div></td>' +
        '<td><div class="skeleton" style="width:120px"></div></td>' +
        '<td><div class="skeleton" style="width:180px"></div></td>' +
        '<td><div class="skeleton" style="width:110px"></div></td>' +
        '<td><div class="skeleton" style="width:90px"></div></td>' +
        '<td></td></tr>';
    }
    return rows;
  }

  function findingsQuery() {
    var filters = state.findings.filters;
    var params = [
      'limit=' + state.findings.limit,
      'ack=' + encodeURIComponent(filters.ack),
      'severity=' + encodeURIComponent(filters.severity),
      'category=' + encodeURIComponent(filters.category)
    ];
    if (filters.q) params.push('q=' + encodeURIComponent(filters.q));
    return params.join('&');
  }

  function refreshFindings() {
    var findings = state.findings;
    findings.selected = {};
    findings.selectedCount = 0;
    renderSelectionBar();
    return api('/api/findings?' + findingsQuery()).then(function (data) {
      findings.items = data.items || [];
      findings.counts = data.counts || {};
      findings.total = data.total || 0;
      findings.hasMore = !!data.has_more;
      renderFindingsRows();
      renderSeverityCounts();
      renderFoot();
    });
  }

  function loadMoreFindings() {
    var findings = state.findings;
    findings.limit += 100;
    api('/api/findings?' + findingsQuery()).then(function (data) {
      findings.items = data.items || [];
      findings.total = data.total || 0;
      findings.hasMore = !!data.has_more;
      renderFindingsRows();
      renderFoot();
    });
  }

  function renderSeverityCounts() {
    var counts = state.findings.counts;
    counts.all = Object.keys(counts).reduce(function (acc, key) {
      return acc + Number(counts[key] || 0);
    }, 0);
    $$('#sev-filter button').forEach(function (button) {
      var key = button.dataset.value;
      var countEl = button.querySelector('.count');
      if (countEl) countEl.textContent = num(counts[key] || 0);
      button.classList.toggle('active', state.findings.filters.severity === key);
    });
  }

  function renderFindingsRows() {
    var body = $('#findings-body');
    if (!body) return;
    var items = state.findings.items;
    if (!items.length) {
      body.innerHTML =
        '<tr><td colspan="7"><div class="empty">' +
        '<div class="empty-icon">' +
        ICON.empty +
        '</div><h3>没有符合条件的命中</h3>' +
        '<p>换一个筛选条件，或先执行一次扫描。</p>' +
        '<button class="btn btn-sm" data-action="open-scan">立即扫描</button></div></td></tr>';
      return;
    }
    body.innerHTML = items
      .map(function (item) {
        var checked = state.findings.selected[item.id] ? ' checked' : '';
        return (
          '<tr class="clickable" data-action="open-finding" data-id="' +
          item.id +
          '">' +
          '<td><input type="checkbox" data-select="' +
          item.id +
          '"' +
          checked +
          '></td>' +
          '<td>' +
          sevChip(item.severity) +
          '</td>' +
          '<td><div style="font-weight:500">' +
          esc(item.rule_name) +
          '</div><div class="small muted">' +
          esc(item.category_label) +
          '</div></td>' +
          '<td class="path-cell"><span class="path-name" title="' +
          attr(item.path) +
          '">' +
          esc(fileName(item.path)) +
          '</span><span class="path-dir">' +
          esc(shortPath(dirName(item.path))) +
          '</span><span class="line-no">第 ' +
          item.line +
          ' 行</span></td>' +
          '<td class="mono-cell">' +
          esc(item.masked) +
          '</td>' +
          '<td class="time-cell small muted">' +
          esc(item.detected_at_text) +
          '</td>' +
          '<td class="small">' +
          (item.acknowledged ? '<span class="muted">已确认</span>' : '待处理') +
          '</td></tr>'
        );
      })
      .join('');
    var all = $('#select-all');
    if (all) all.checked = false;
  }

  function renderFoot() {
    var foot = $('#findings-foot');
    if (!foot) return;
    var findings = state.findings;
    foot.innerHTML =
      '<span class="muted small">共 ' +
      num(findings.total) +
      ' 条，已显示 ' +
      num(findings.items.length) +
      ' 条</span><span class="spacer" style="flex:1"></span>' +
      (findings.hasMore
        ? '<button class="btn btn-sm" data-action="load-more">加载更多</button>'
        : '') +
      '<button class="btn btn-sm btn-ghost" data-action="refresh-findings">刷新</button>';
  }

  function renderSelectionBar() {
    var slot = $('#selection-slot');
    if (!slot) return;
    var count = Object.keys(state.findings.selected).length;
    state.findings.selectedCount = count;
    slot.innerHTML = count
      ? '<div class="selection-bar"><span>已选择 ' +
        count +
        ' 条</span><span class="spacer"></span>' +
        '<button class="btn" data-action="ack-selected">标记为已确认</button>' +
        '<button class="btn" data-action="clear-selection">取消选择</button></div>'
      : '';
  }

  function selectAll(checked) {
    state.findings.selected = {};
    if (checked) {
      state.findings.items.forEach(function (item) {
        state.findings.selected[item.id] = true;
      });
    }
    $$('#findings-body input[data-select]').forEach(function (box) {
      box.checked = checked;
    });
    renderSelectionBar();
  }

  /* ---------------------------------------------------------------- rules */

  function loadRulesView() {
    return api('/api/rules').then(function (data) {
      state.rules = data;
      $('#view').innerHTML = rulesHtml();
    });
  }

  function ruleCategories() {
    var categories = {};
    ((state.rules && state.rules.items) || []).forEach(function (rule) {
      categories[rule.category] = rule.category_label;
    });
    return categories;
  }

  function rulesHtml() {
    var data = state.rules;
    var categories = ruleCategories();
    var chips = ['<button class="btn btn-sm' + (state.ruleCategory === 'all' ? ' btn-primary' : '') + '" data-action="set-rule-category" data-value="all">全部 ' + data.items.length + '</button>'];
    Object.keys(categories).forEach(function (key) {
      var active = state.ruleCategory === key;
      chips.push(
        '<button class="btn btn-sm' +
          (active ? ' btn-primary' : '') +
          '" data-action="set-rule-category" data-value="' +
          attr(key) +
          '">' +
          esc(categories[key]) +
          '</button>'
      );
    });

    return (
      '<div class="stack">' +
      '<section class="card"><div class="card-head"><h2>规则测试</h2>' +
      '<span class="spacer"></span><span class="muted">在本机执行，不会上传任何内容</span></div>' +
      '<div class="card-body">' +
      '<textarea class="textarea" id="rule-test-input" style="min-height:110px" placeholder="粘贴一段文本，立即用当前启用的规则检测。例如：\n联系人 13812345678，身份证 11010519491231002X，password = &quot;Aa123456!&quot;"></textarea>' +
      '<div style="display:flex;gap:8px;align-items:center;margin-top:10px">' +
      '<button class="btn btn-primary" data-action="test-rules">开始测试</button>' +
      '<button class="btn btn-ghost" data-action="clear-test">清空</button>' +
      '<span class="small muted">结果同样只显示脱敏值</span></div>' +
      '<div id="test-result"></div>' +
      '</div></section>' +

      '<section class="card"><div class="card-head"><h2>规则列表</h2>' +
      '<span class="spacer"></span><span class="muted" id="rule-summary">启用 ' +
      data.active +
      ' / ' +
      data.total +
      ' 条 · 最低记录级别 ' +
      esc(SEV_LABEL[data.min_severity] || data.min_severity) +
      '</span></div>' +
      '<div class="card-body">' +
      '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">' +
      chips.join('') +
      '<input class="input" id="rule-search" style="width:220px;margin-left:auto" placeholder="搜索规则名或 ID" value="' +
      attr(state.ruleQuery) +
      '">' +
      '</div>' +
      '<div id="rule-grid">' +
      ruleGridHtml() +
      '</div></div></section>' +
      '</div>'
    );
  }

  function ruleGridHtml() {
    var items = ((state.rules && state.rules.items) || []).filter(function (rule) {
      if (state.ruleCategory !== 'all' && rule.category !== state.ruleCategory) return false;
      if (!state.ruleQuery) return true;
      var query = state.ruleQuery.toLowerCase();
      return (
        rule.name.toLowerCase().indexOf(query) >= 0 ||
        rule.id.toLowerCase().indexOf(query) >= 0 ||
        (rule.description || '').toLowerCase().indexOf(query) >= 0
      );
    });
    if (!items.length) {
      return '<div class="empty"><div class="empty-icon">' + ICON.empty + '</div><h3>没有匹配的规则</h3></div>';
    }
    return (
      '<div class="rule-grid">' +
      items
        .map(function (rule) {
          var tags = (rule.validators || [])
            .map(function (validator) {
              return '<span class="tag">' + esc(validator) + '</span>';
            })
            .join('');
          return (
            '<article class="rule-card' +
            (rule.enabled ? '' : ' is-off') +
            '"><div class="rule-top"><div style="min-width:0">' +
            '<div class="rule-name">' +
            esc(rule.name) +
            '</div><div class="rule-id">' +
            esc(rule.id) +
            '</div></div>' +
            '<span style="flex:1"></span>' +
            '<label class="switch"><input type="checkbox" data-rule-toggle="' +
            attr(rule.id) +
            '"' +
            (rule.enabled ? ' checked' : '') +
            '><span></span></label></div>' +
            '<div class="rule-meta">' +
            sevChip(rule.severity) +
            '<span class="tag">' +
            esc(rule.category_label) +
            '</span>' +
            tags +
            (rule.builtin ? '' : '<span class="tag">自定义</span>') +
            '</div>' +
            '<p class="rule-desc">' +
            esc(rule.description || '—') +
            '</p></article>'
          );
        })
        .join('') +
      '</div>'
    );
  }

  function toggleRule(id, enabled) {
    api('/api/rules/toggle', { method: 'POST', body: { id: id, enabled: enabled } })
      .then(function () {
        toast(
          enabled
            ? '已启用「' + id + '」，下次扫描会自动对未变化文件重扫'
            : '已关闭「' + id + '」，下次扫描生效'
        );
        return api('/api/rules');
      })
      .then(function (data) {
        state.rules = data;
        $('#rule-grid').innerHTML = ruleGridHtml();
        var summary = $('#rule-summary');
        if (summary) {
          summary.textContent =
            '启用 ' +
            data.active +
            ' / ' +
            data.total +
            ' 条 · 最低记录级别 ' +
            (SEV_LABEL[data.min_severity] || data.min_severity);
        }
      })
      .catch(function (error) {
        toast(error.message, { type: 'error' });
      });
  }

  function runRuleTest() {
    var input = $('#rule-test-input');
    var result = $('#test-result');
    if (!input || !result) return;
    var text = input.value;
    if (!text.trim()) {
      toast('请先粘贴一段文本');
      return;
    }
    result.innerHTML = '<div class="test-result"><div class="test-result-head">正在检测…</div></div>';
    api('/api/rules/test', { method: 'POST', body: { text: text } })
      .then(function (data) {
        if (!data.items.length) {
          result.innerHTML =
            '<div class="test-result"><div class="test-result-head">未命中任何规则（当前启用的 ' +
            state.rules.active +
            ' 条规则）</div></div>';
          return;
        }
        result.innerHTML =
          '<div class="test-result"><div class="test-result-head">命中 ' +
          data.total +
          ' 处（值已脱敏）</div>' +
          data.items
            .map(function (item) {
              return (
                '<div class="test-hit">' +
                sevChip(item.severity) +
                '<span>' +
                esc(item.rule_name) +
                '</span><span class="masked">' +
                esc(item.masked) +
                '</span><span class="small muted" style="margin-left:auto">第 ' +
                item.line +
                ' 行</span></div>'
              );
            })
            .join('') +
          '</div>';
      })
      .catch(function (error) {
        result.innerHTML = '<div class="warn-line">' + esc(error.message) + '</div>';
      });
  }

  /* ------------------------------------------------------------- settings */

  function loadSettingsView() {
    return api('/api/settings').then(function (data) {
      state.settings = data;
      state.draftRoots = (data.scan.roots || []).slice();
      $('#view').innerHTML = settingsHtml();
    });
  }

  function settingsHtml() {
    var data = state.settings;
    var scan = data.scan;
    var rootsAuto = scan.roots_auto;

    var rootChips = rootsAuto
      ? (scan.effective_roots || [])
          .map(function (root) {
            return '<span class="path-chip"><span>' + esc(shortPath(root)) + '</span></span>';
          })
          .join('')
      : (state.draftRoots || [])
          .map(function (root, index) {
            return (
              '<span class="path-chip"><span>' +
              esc(shortPath(root)) +
              '</span><button data-action="remove-root" data-index="' +
              index +
              '" title="移除">' +
              ICON.close +
              '</button></span>'
            );
          })
          .join('');

    return (
      '<div class="stack">' +
      section('扫描范围', '未指定时自动扫描系统常用目录（含麒麟/Linux 的中文目录名）', [
        rowHtml(
          '扫描目录',
          rootsAuto ? '当前使用系统默认目录；添加自定义目录后只扫描下列目录' : '仅扫描下列目录',
          '<div class="chips">' +
            (rootChips || '<span class="small muted">未找到可用目录</span>') +
            '<button class="btn btn-sm" data-action="add-root">添加目录</button>' +
            (!rootsAuto
              ? '<button class="btn btn-sm btn-primary" data-action="save-roots">保存</button>'
              : '') +
            '</div>',
          'stacked'
        ),
        rowHtml(
          '单文件大小上限',
          '超过后跳过并写入日志，避免大文件拖慢扫描',
          '<input class="input narrow" type="number" min="1" value="' +
            scan.max_file_size_mb +
            '" data-setting="scan.max_file_size_mb"> <span class="small muted">MB</span>'
        ),
        rowHtml(
          '扫描线程数',
          '0 表示自动（CPU 核数，最多 8）；机械硬盘建议 2–4',
          '<input class="input narrow" type="number" min="0" value="' +
            scan.threads +
            '" data-setting="scan.threads">'
        ),
        rowHtml(
          'Office 文档抽取',
          '直接读取 .docx / .xlsx / .pptx 内部文本',
          switchHtml('scan.office_documents', scan.office_documents)
        ),
        rowHtml(
          '跳过隐藏文件',
          '文件或目录名以 . 开头时跳过',
          switchHtml('scan.skip_hidden', scan.skip_hidden)
        ),
        rowHtml(
          '跟随符号链接',
          '可能造成重复扫描，建议保持关闭',
          switchHtml('scan.follow_symlinks', scan.follow_symlinks)
        ),
        rowHtml(
          '定时全量对账',
          '守护进程每隔多少小时做一次对账；0 表示关闭',
          '<input class="input narrow" type="number" min="0" value="' +
            scan.full_scan_interval_hours +
            '" data-setting="scan.full_scan_interval_hours"> <span class="small muted">小时</span>'
        ),
        rowHtml(
          '启动时对账',
          '守护进程/开机自启后先执行一次增量对账',
          switchHtml('scan.scan_on_startup', scan.scan_on_startup)
        )
      ]) +

      section('检测与记录', '低于最低级别的命中不会被记录，也不会提醒', [
        rowHtml(
          '最低记录级别',
          '身份证、银行卡等默认高危；提示类主要用于调试',
          selectHtml('rules.min_severity', data.rules.min_severity, [
            ['info', '提示'],
            ['low', '低危'],
            ['medium', '中危'],
            ['high', '高危'],
            ['critical', '严重']
          ])
        ),
        rowHtml(
          '已关闭规则',
          '在「检测规则」页面可逐条开关',
          '<span class="small muted">' +
            (data.rules.disabled.length ? data.rules.disabled.length + ' 条已关闭' : '全部启用') +
            '</span>'
        ),
        rowHtml(
          '自定义规则',
          '自定义规则需在配置文件中以 [[rules.custom]] 添加',
          '<span class="small muted">' + data.rules.custom_count + ' 条</span>'
        )
      ]) +

      section('通知', '命中后通过系统通知提醒（Windows Toast / macOS 通知中心 / notify-send）', [
        rowHtml('启用桌面通知', '关闭后只记录不提醒', switchHtml('notify.enabled', data.notify.enabled)),
        rowHtml(
          '最低通知级别',
          '低于该级别不弹窗',
          selectHtml('notify.min_severity', data.notify.min_severity, [
            ['low', '低危'],
            ['medium', '中危'],
            ['high', '高危'],
            ['critical', '严重']
          ])
        ),
        rowHtml(
          '通知方式',
          'summary 每批聚合一次；per_file 每个文件一条；off 不弹窗',
          selectHtml('notify.mode', data.notify.mode, [
            ['summary', '聚合提醒'],
            ['per_file', '逐文件提醒'],
            ['off', '不弹窗']
          ])
        ),
        rowHtml(
          '测试通知链路',
          '发送一条测试通知，确认系统通知权限已开启',
          '<button class="btn btn-sm" data-action="test-notify">发送测试通知</button>'
        )
      ]) +

      section('存储与隐私', '默认只保存脱敏值；数据库位于本机用户数据目录', [
        rowHtml(
          '记录保留天数',
          '超期记录会在下次扫描时清理；0 表示永久保留',
          '<input class="input narrow" type="number" min="0" value="' +
            data.storage.retention_days +
            '" data-setting="storage.retention_days"> <span class="small muted">天</span>'
        ),
        rowHtml(
          '保存命中原文',
          '开启后数据库会保存敏感数据原文，不推荐',
          switchHtml('storage.store_raw_match', data.storage.store_raw_match)
        ),
        rowHtml('数据库文件', 'SQLite，仅本机可读（权限 0600）', '<span class="small mono muted" style="max-width:420px;overflow:hidden;text-overflow:ellipsis">' + esc(data.paths.database) + '</span>')
      ]) +

      section('系统集成', '使用当前用户身份，无需管理员权限', [
        rowHtml(
          '开机自启',
          '<pre style="margin:4px 0 0;font-size:11.5px;color:var(--text-3);white-space:pre-wrap">' +
            esc(data.autostart.detail) +
            '</pre>',
          '<button class="btn btn-sm" data-action="autostart-install">安装</button>' +
            '<button class="btn btn-sm btn-ghost" data-action="autostart-remove">移除</button>'
        ),
        rowHtml(
          '文件与配置',
          '打开数据目录、报告目录或直接编辑 config.toml',
          '<button class="btn btn-sm" data-action="open-target" data-target="data">数据目录</button>' +
            '<button class="btn btn-sm" data-action="open-target" data-target="config">配置位置</button>' +
            '<button class="btn btn-sm" data-action="edit-config">编辑配置</button>'
        )
      ]) +

      section('关于', '', [
        rowHtml(
          '版本信息',
          '数据哨兵 DataSentinel · 单文件可执行 · 无运行时依赖',
          '<span class="small muted">' +
            esc(CONF.platform) +
            ' · v' +
            esc(CONF.version) +
            '</span>'
        ),
        rowHtml(
          '隐私说明',
          '所有检出结果保存在本机 SQLite；控制台只监听 127.0.0.1，退出即停止。',
          '<span class="small muted">数据不出本机</span>'
        )
      ]) +
      '</div>'
    );
  }

  function section(title, desc, rows) {
    return (
      '<section class="card"><div class="card-head"><div><h2>' +
      esc(title) +
      '</h2>' +
      (desc ? '<div class="small muted" style="margin-top:2px">' + desc + '</div>' : '') +
      '</div></div>' +
      rows.join('') +
      '</section>'
    );
  }

  function rowHtml(title, desc, control, extra) {
    return (
      '<div class="setting-row' +
      (extra ? ' ' + extra : '') +
      '"><div class="setting-main"><div class="setting-title">' +
      esc(title) +
      '</div>' +
      (desc ? '<div class="setting-desc">' + desc + '</div>' : '') +
      '</div><div class="setting-control">' +
      control +
      '</div></div>'
    );
  }

  function switchHtml(setting, checked) {
    return (
      '<label class="switch"><input type="checkbox" data-setting="' +
      attr(setting) +
      '"' +
      (checked ? ' checked' : '') +
      '><span></span></label>'
    );
  }

  function selectHtml(setting, value, options) {
    return (
      '<select class="select" data-setting="' +
      attr(setting) +
      '">' +
      options
        .map(function (option) {
          return (
            '<option value="' +
            attr(option[0]) +
            '"' +
            (option[0] === value ? ' selected' : '') +
            '>' +
            esc(option[1]) +
            '</option>'
          );
        })
        .join('') +
      '</select>'
    );
  }

  function saveSetting(setting, value) {
    var parts = setting.split('.');
    var body = {};
    body[parts[0]] = {};
    body[parts[0]][parts[1]] = value;
    return api('/api/settings', { method: 'POST', body: body }).then(function () {
      toast('已保存');
    });
  }

  function saveRoots() {
    api('/api/settings', { method: 'POST', body: { scan: { roots: state.draftRoots || [] } } })
      .then(function () {
        toast('扫描目录已保存，下次扫描生效');
        return loadSettingsView();
      })
      .catch(function (error) {
        toast(error.message, { type: 'error' });
      });
  }

  /* ---------------------------------------------------------------- scan */

  function renderScanBanner() {
    var slot = $('#scan-banner');
    if (!slot) return;
    var scan = state.scan || {};
    if (scan.running) {
      var elapsed = scan.started_at
        ? Math.max(0, Math.floor(Date.now() / 1000 - scan.started_at))
        : 0;
      slot.innerHTML =
        '<div class="scan-strip"><div class="spinner"></div>' +
        '<div class="scan-strip-main"><strong>正在扫描…</strong><span>已检查 ' +
        num(scan.files_seen || 0) +
        ' 个文件 · 已分析 ' +
        num(scan.files_scanned || 0) +
        ' 个 · 命中 ' +
        num(scan.findings || 0) +
        ' 处' +
        (scan.force ? ' · 强制全量' : '') +
        '</span></div>' +
        '<div class="scan-strip-time">' +
        elapsed +
        's</div></div>';
      return;
    }
    if (scan.error) {
      slot.innerHTML =
        '<div class="scan-strip" style="border-color:#f3c6c2"><div class="scan-strip-main"><strong>扫描未完成</strong><span>' +
        esc(scan.error) +
        '</span></div><button class="icon-btn" data-action="dismiss-scan-error">' +
        ICON.close +
        '</button></div>';
      return;
    }
    slot.innerHTML = '';
  }

  function startPolling() {
    if (state.poll) return;
    state.poll = setInterval(tickScan, 800);
    tickScan();
  }
  function stopPolling() {
    if (state.poll) {
      clearInterval(state.poll);
      state.poll = null;
    }
  }

  function tickScan() {
    api('/api/scan/status')
      .then(function (status) {
        state.scan = status;
        renderScanBanner();
        if (!status.running) {
          stopPolling();
          if (status.error) {
            toast('扫描失败：' + status.error, { type: 'error', duration: 7000 });
          } else if (status.last) {
            var summary = status.last.summary || {};
            toast(
              '扫描完成：分析 ' +
                num(summary.files_scanned) +
                ' 个文件，命中 ' +
                num(summary.findings) +
                ' 处（新增 ' +
                num(summary.new_findings) +
                '）',
              {
                duration: 6000,
                action: {
                  label: '查看命中',
                  onClick: function () {
                    location.hash = '#/findings';
                  }
                }
              }
            );
          }
          refreshCurrentRoute();
        }
      })
      .catch(function () {
        stopPolling();
      });
  }

  function openScanModal() {
    if (state.overview && state.overview.roots) {
      state.scanDraft = { paths: state.overview.roots.slice(), force: false, notify: true };
      renderScanModal();
      return;
    }
    api('/api/settings')
      .then(function (data) {
        state.settings = data;
        state.scanDraft = {
          paths: (data.scan.effective_roots || []).slice(),
          force: false,
          notify: true
        };
        renderScanModal();
      })
      .catch(function (error) {
        toast(error.message, { type: 'error' });
      });
  }

  function renderScanModal() {
    var draft = state.scanDraft || { paths: [], force: false, notify: true };
    var html =
      '<div class="modal"><div class="modal-head"><h3>开始扫描</h3><span class="spacer"></span>' +
      '<button class="icon-btn" data-action="close-modal">' +
      ICON.close +
      '</button></div>' +
      '<div class="modal-body">' +
      '<div class="form-row"><span class="form-label">扫描范围</span>' +
      '<div class="chips">' +
      (draft.paths.length
        ? draft.paths
            .map(function (path, index) {
              return (
                '<span class="path-chip"><span>' +
                esc(shortPath(path)) +
                '</span><button data-action="scan-remove-path" data-index="' +
                index +
                '">' +
                ICON.close +
                '</button></span>'
              );
            })
            .join('')
        : '<span class="small muted">未选择目录，将使用系统默认常用目录</span>') +
      '<button class="btn btn-sm" data-action="scan-add-path">添加目录</button>' +
      '</div>' +
      '<div class="form-hint">默认按 size + mtime 增量扫描，只分析新增或修改过的文件。</div></div>' +
      '<div class="form-row"><label class="checkbox"><input type="checkbox" id="scan-force"' +
      (draft.force ? ' checked' : '') +
      '><span>强制全量重扫<span class="hint">忽略增量台账，逐个文件重新检测（耗时更长）</span></span></label></div>' +
      '<div class="form-row"><label class="checkbox"><input type="checkbox" id="scan-notify"' +
      (draft.notify ? ' checked' : '') +
      '><span>完成后发送系统通知<span class="hint">按通知设置聚合提醒</span></span></label></div>' +
      '</div>' +
      '<div class="modal-foot"><button class="btn" data-action="close-modal">取消</button>' +
      '<button class="btn btn-primary" data-action="start-scan">开始扫描</button></div></div>';
    if (state.modalStack.length) {
      replaceModal(html);
    } else {
      pushModal(html);
    }
  }

  function startScan() {
    var forceEl = $('#scan-force');
    var notifyEl = $('#scan-notify');
    var body = {
      paths: (state.scanDraft && state.scanDraft.paths) || [],
      force: !!(forceEl && forceEl.checked),
      notify: !(notifyEl && !notifyEl.checked)
    };
    closeAllModals();
    api('/api/scan/start', { method: 'POST', body: body })
      .then(function () {
        state.scan = { running: true, started_at: Math.floor(Date.now() / 1000) };
        renderScanBanner();
        startPolling();
      })
      .catch(function (error) {
        toast(error.message, { type: 'error' });
        if (error.status === 409) {
          startPolling();
        }
      });
  }

  /* ---------------------------------------------------------- dir picker */

  function openDirPicker(startPath, onPick) {
    state.pickerPick = onPick || null;
    state.pickerOpen = true;
    loadDirInto(startPath || '', true);
  }

  function loadDirInto(path, push) {
    api('/api/fs/list?path=' + encodeURIComponent(path || ''))
      .then(function (data) {
        state.pickerPath = data.path;
        var html = dirPickerHtml(data);
        if (push) {
          pushModal(html);
        } else {
          replaceModal(html);
        }
      })
      .catch(function (error) {
        toast(error.message, { type: 'error' });
      });
  }

  function dirPickerHtml(data) {
    var items = (data.dirs || [])
      .map(function (dir) {
        return (
          '<button class="dir-item" data-action="dir-enter" data-path="' +
          attr(dir.path) +
          '">' +
          ICON.folder +
          '<span>' +
          esc(dir.name) +
          '</span>' +
          (dir.hidden ? '<span class="hidden-flag">隐藏</span>' : '') +
          '</button>'
        );
      })
      .join('');
    return (
      '<div class="modal"><div class="modal-head"><h3>选择目录</h3><span class="spacer"></span>' +
      '<button class="icon-btn" data-action="picker-cancel">' +
      ICON.close +
      '</button></div>' +
      '<div class="modal-body"><div class="dir-picker">' +
      '<div class="shortcut-row">' +
      (data.shortcuts || [])
        .map(function (shortcut) {
          return (
            '<button class="btn btn-sm" data-action="dir-enter" data-path="' +
            attr(shortcut.path) +
            '">' +
            esc(shortcut.label) +
            '</button>'
          );
        })
        .join('') +
      (data.parent
        ? '<button class="btn btn-sm" data-action="dir-enter" data-path="' +
          attr(data.parent) +
          '">' +
          ICON.up +
          ' 上一级</button>'
        : '') +
      '</div>' +
      '<div class="dir-path">' +
      ICON.folder +
      '<span>' +
      esc(data.path) +
      '</span></div>' +
      '<div class="dir-list">' +
      (items || '<div class="empty"><p>该目录下没有子目录</p></div>') +
      '</div></div></div>' +
      '<div class="modal-foot"><button class="btn" data-action="picker-cancel">取消</button>' +
      '<button class="btn btn-primary" data-action="picker-choose">选择此目录</button></div></div>'
    );
  }

  function closePicker() {
    state.pickerOpen = false;
    state.pickerPick = null;
    popModal();
  }

  /* ------------------------------------------------------------ actions */

  function findFinding(id) {
    var all = state.findings.items.concat(state.recent || []);
    for (var i = 0; i < all.length; i += 1) {
      if (String(all[i].id) === String(id)) return all[i];
    }
    return null;
  }

  function acknowledge(ids, all) {
    return api('/api/findings/ack', { method: 'POST', body: all ? { all: true } : { ids: ids } }).then(
      function (data) {
        toast('已确认 ' + data.updated + ' 条');
        closeDrawer();
        return api('/api/overview')
          .then(function (overview) {
            state.overview = overview;
            updateTopbar();
          })
          .catch(function () {})
          .then(function () {
            refreshCurrentRoute();
          });
      }
    );
  }

  function exportReport() {
    pushModal(
      '<div class="modal"><div class="modal-head"><h3>导出报告</h3><span class="spacer"></span>' +
        '<button class="icon-btn" data-action="close-modal">' +
        ICON.close +
        '</button></div>' +
        '<div class="modal-body">' +
        '<div class="form-row"><span class="form-label">报告格式</span>' +
        '<select class="select" id="report-format" style="width:100%"><option value="html">HTML（可直接打开查看）</option><option value="json">JSON（便于二次处理）</option></select></div>' +
        '<div class="form-row"><span class="form-label">时间范围</span>' +
        '<select class="select" id="report-days" style="width:100%"><option value="7">最近 7 天</option><option value="30" selected>最近 30 天</option><option value="90">最近 90 天</option><option value="0">全部记录</option></select>' +
        '<div class="form-hint">报告只包含脱敏值，默认写入本机报告目录。</div></div></div>' +
        '<div class="modal-foot"><button class="btn" data-action="close-modal">取消</button>' +
        '<button class="btn btn-primary" data-action="do-export">生成报告</button></div></div>'
    );
  }

  function doExport() {
    var format = ($('#report-format') || {}).value || 'html';
    var days = Number(($('#report-days') || {}).value || 30);
    closeAllModals();
    toast('正在生成报告…');
    api('/api/report', { method: 'POST', body: { format: format, days: days } })
      .then(function (data) {
        toast('报告已生成', {
          duration: 8000,
          action: {
            label: '在文件夹中显示',
            onClick: function () {
              api('/api/reveal', { method: 'POST', body: { path: data.path } }).catch(function (error) {
                toast(error.message, { type: 'error' });
              });
            }
          }
        });
      })
      .catch(function (error) {
        toast(error.message, { type: 'error' });
      });
  }

  function editConfig() {
    api('/api/config')
      .then(function (data) {
        pushModal(
          '<div class="modal wide"><div class="modal-head"><h3>编辑配置文件</h3><span class="spacer"></span>' +
            '<span class="small muted">' +
            esc(data.path) +
            '</span></div>' +
            '<div class="modal-body"><textarea class="textarea" id="config-text" style="min-height:380px">' +
            esc(data.toml) +
            '</textarea>' +
            '<div class="form-hint">保存前会校验 TOML 与字段合法性；原文件会备份为 config.toml.bak。</div></div>' +
            '<div class="modal-foot"><button class="btn" data-action="close-modal">取消</button>' +
            '<button class="btn btn-primary" data-action="save-config">保存</button></div></div>'
        );
      })
      .catch(function (error) {
        toast(error.message, { type: 'error' });
      });
  }

  /* --------------------------------------------------------- event wiring */

  document.addEventListener('click', function (event) {
    if (event.target.closest('input[type="checkbox"]')) return;
    var target = event.target.closest('[data-action]');
    if (!target) return;
    var action = target.dataset.action;

    switch (action) {
      case 'close-drawer':
        closeDrawer();
        break;
      case 'close-modal':
        closeAllModals();
        break;
      case 'modal-backdrop':
        if (event.target === target) closeAllModals();
        break;
      case 'reload':
        renderRoute();
        break;
      case 'open-scan':
        openScanModal();
        break;
      case 'start-scan':
        startScan();
        break;
      case 'dismiss-scan-error':
        state.scan.error = null;
        renderScanBanner();
        break;
      case 'open-finding': {
        var item = findFinding(target.dataset.id);
        if (item) openFinding(item);
        break;
      }
      case 'ack-finding': {
        var id = target.dataset.id;
        acknowledge([Number(id)], false).catch(function (error) {
          toast(error.message, { type: 'error' });
        });
        break;
      }
      case 'unack-finding':
        toast('已确认的记录会保留在数据库中，暂不支持撤回');
        break;      case 'copy':
        copyText(target.dataset.text || '');
        break;
      case 'reveal':
        api('/api/reveal', { method: 'POST', body: { path: target.dataset.path } }).catch(function (
          error
        ) {
          toast(error.message, { type: 'error' });
        });
        break;
      case 'set-severity':
        state.findings.filters.severity = target.dataset.value;
        refreshFindings().catch(function (error) {
          toast(error.message, { type: 'error' });
        });
        break;
      case 'load-more':
        loadMoreFindings();
        break;
      case 'refresh-findings':
        refreshFindings().catch(function (error) {
          toast(error.message, { type: 'error' });
        });
        break;
      case 'clear-selection':
        selectAll(false);
        break;
      case 'ack-selected': {
        var selected = Object.keys(state.findings.selected).map(Number);
        if (!selected.length) return;
        acknowledge(selected, false).catch(function (error) {
          toast(error.message, { type: 'error' });
        });
        break;
      }
      case 'ack-all':
        confirmDialog('确认全部命中？', '所有未确认的命中都会被标记为已确认，之后不再重复提醒。', function () {
          acknowledge([], true).catch(function (error) {
            toast(error.message, { type: 'error' });
          });
        });
        break;
      case 'export-report':
        exportReport();
        break;
      case 'do-export':
        doExport();
        break;
      case 'set-rule-category':
        state.ruleCategory = target.dataset.value;
        $$('#view [data-action="set-rule-category"]').forEach(function (button) {
          button.classList.toggle('btn-primary', button.dataset.value === state.ruleCategory);
        });
        $('#rule-grid').innerHTML = ruleGridHtml();
        break;
      case 'test-rules':
        runRuleTest();
        break;
      case 'clear-test':
        $('#rule-test-input').value = '';
        $('#test-result').innerHTML = '';
        break;
      case 'add-root':
        openDirPicker('', function (path) {
          if (state.settings.scan.roots_auto) {
            state.draftRoots = (state.settings.scan.effective_roots || []).slice();
          }
          if (state.draftRoots.indexOf(path) < 0) state.draftRoots.push(path);
          state.settings.scan.roots = state.draftRoots.slice();
          state.settings.scan.roots_auto = false;
          $('#view').innerHTML = settingsHtml();
        });
        break;
      case 'remove-root': {
        var index = Number(target.dataset.index);
        state.draftRoots.splice(index, 1);
        state.settings.scan.roots = state.draftRoots.slice();
        state.settings.scan.roots_auto = state.draftRoots.length === 0;
        $('#view').innerHTML = settingsHtml();
        break;
      }
      case 'save-roots':
        saveRoots();
        break;
      case 'scan-add-path':
        openDirPicker('', function (path) {
          if (state.scanDraft.paths.indexOf(path) < 0) state.scanDraft.paths.push(path);
          renderScanModal();
        });
        break;
      case 'scan-remove-path': {
        var pathIndex = Number(target.dataset.index);
        state.scanDraft.paths.splice(pathIndex, 1);
        renderScanModal();
        break;
      }
      case 'dir-enter':
        loadDirInto(target.dataset.path, false);
        break;
      case 'picker-cancel':
        closePicker();
        break;
      case 'picker-choose': {
        var pick = state.pickerPick;
        var chosen = state.pickerPath;
        state.pickerOpen = false;
        popModal();
        if (pick) pick(chosen);
        break;
      }
      case 'test-notify':
        api('/api/notify/test', { method: 'POST' })
          .then(function () {
            toast('测试通知已发送，请检查系统通知中心');
          })
          .catch(function (error) {
            toast(error.message, { type: 'error' });
          });
        break;
      case 'autostart-install':
      case 'autostart-remove': {
        var act = action === 'autostart-install' ? 'install' : 'uninstall';
        api('/api/autostart', { method: 'POST', body: { action: act } })
          .then(function () {
            toast(act === 'install' ? '已安装开机自启' : '已移除开机自启');
            loadSettingsView();
          })
          .catch(function (error) {
            toast(error.message, { type: 'error' });
          });
        break;
      }
      case 'open-target':
        api('/api/open', { method: 'POST', body: { target: target.dataset.target } }).catch(function (
          error
        ) {
          toast(error.message, { type: 'error' });
        });
        break;
      case 'edit-config':
        editConfig();
        break;
      case 'save-config': {
        var toml = ($('#config-text') || {}).value || '';
        api('/api/config', { method: 'POST', body: { toml: toml } })
          .then(function () {
            closeAllModals();
            toast('配置已保存');
            loadSettingsView();
          })
          .catch(function (error) {
            toast(error.message, { type: 'error', duration: 6000 });
          });
        break;
      }
      default:
        break;
    }
  });

  document.addEventListener('change', function (event) {
    var ruleToggle = event.target.closest('[data-rule-toggle]');
    if (ruleToggle) {
      toggleRule(ruleToggle.dataset.ruleToggle, ruleToggle.checked);
      return;
    }
    if (event.target.id === 'select-all') {
      selectAll(event.target.checked);
      return;
    }
    var select = event.target.closest('[data-select]');
    if (select) {
      if (select.checked) state.findings.selected[select.dataset.select] = true;
      else delete state.findings.selected[select.dataset.select];
      renderSelectionBar();
      return;
    }
    if (event.target.id === 'ack-filter') {
      state.findings.filters.ack = event.target.value;
      refreshFindings().catch(function (error) {
        toast(error.message, { type: 'error' });
      });
      return;
    }
    if (event.target.id === 'category-filter') {
      state.findings.filters.category = event.target.value;
      refreshFindings().catch(function (error) {
        toast(error.message, { type: 'error' });
      });
      return;
    }
    if (event.target.id === 'rule-search') {
      state.ruleQuery = event.target.value;
      $('#rule-grid').innerHTML = ruleGridHtml();
      return;
    }
    var setting = event.target.closest('[data-setting]');
    if (setting) {
      var key = setting.dataset.setting;
      var value =
        setting.type === 'checkbox'
          ? setting.checked
          : setting.type === 'number'
          ? Number(setting.value)
          : setting.value;
      if (key === 'storage.store_raw_match' && value === true) {
        setting.checked = false;
        confirmDialog(
          '确认保存命中原文？',
          '开启后数据库会以明文保存身份证、密码等敏感值。若本机被入侵，这些数据会被直接读取。建议仅在排查问题时临时开启。',
          function () {
            setting.checked = true;
            saveSetting(key, true).catch(function (error) {
              toast(error.message, { type: 'error' });
            });
          }
        );
        return;
      }
      saveSetting(key, value).catch(function (error) {
        toast(error.message, { type: 'error' });
      });
    }
  });

  document.addEventListener('input', function (event) {
    if (event.target.id === 'search-input') {
      var value = event.target.value;
      debouncedSearch(value);
    }
  });

  var debouncedSearch = debounce(function (value) {
    state.findings.filters.q = value.trim();
    refreshFindings().catch(function (error) {
      toast(error.message, { type: 'error' });
    });
  }, 240);

  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') {
      if (state.modalStack.length) closeAllModals();
      else if (document.body.classList.contains('drawer-open')) closeDrawer();
      return;
    }
    var typing =
      event.target &&
      (event.target.tagName === 'INPUT' ||
        event.target.tagName === 'TEXTAREA' ||
        event.target.tagName === 'SELECT');
    if (!typing && event.key === '/') {
      var search = $('#search-input');
      if (search) {
        event.preventDefault();
        search.focus();
      }
    }
  });

  function confirmDialog(title, message, onConfirm) {
    pushModal(
      '<div class="modal" style="width:440px"><div class="modal-head"><h3>' +
        esc(title) +
        '</h3><span class="spacer"></span><button class="icon-btn" data-action="close-modal">' +
        ICON.close +
        '</button></div>' +
        '<div class="modal-body"><p class="small" style="color:var(--text-2);line-height:1.7">' +
        esc(message) +
        '</p></div>' +
        '<div class="modal-foot"><button class="btn" data-action="close-modal">取消</button>' +
        '<button class="btn btn-primary" id="confirm-ok">确认</button></div></div>'
    );
    var button = $('#confirm-ok');
    if (button) {
      button.addEventListener('click', function () {
        closeAllModals();
        onConfirm();
      });
    }
  }

  window.addEventListener('hashchange', renderRoute);

  renderRoute();
})();
