/* 数据哨兵 · 集中管理控制台 */
(function () {
  'use strict';

  var state = {
    me: null,
    overview: null,
    users: [],
    events: [],
    eventsTotal: 0,
    facets: { users: [], hostnames: [], categories: [], severities: [] },
    agents: [],
    rules: null,
    builtin: [],
    history: [],
    sync: null,
    config: null,
    audit: [],
    filters: { user: '', category: '', severity: '', q: '' },
    page: 0,
    pageSize: 50,
    route: 'overview',
    loading: false
  };

  var SEVERITY_LABEL = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '提示'
  };

  var CATEGORY_LABEL = {
    identity: '身份信息',
    contact: '联系方式',
    financial: '金融账户',
    credential: '账号凭据',
    crypto: '密钥材料',
    internal: '内部数据'
  };

  var ROUTES = {
    overview: { title: '总览', sub: '全部终端的敏感数据告警', load: loadOverview },
    users: { title: '按用户', sub: '按终端使用者聚合的敏感数据类型分布', load: loadUsers },
    events: { title: '告警明细', sub: '按用户、类型、级别与内容筛选', load: loadEvents },
    rules: { title: '规则下发', sub: '统一维护检测规则，客户端按版本自动更新', load: loadRules },
    agents: { title: '终端', sub: '已接入的客户端与规则同步状态', load: loadAgents },
    settings: { title: '服务设置', sub: '接收、保留与审计', load: loadSettings }
  };

  /* ------------------------------------------------------------- 工具 */

  function $(sel, root) {
    return (root || document).querySelector(sel);
  }

  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function num(value) {
    return Number(value || 0).toLocaleString('zh-CN');
  }

  function sevBadge(severity) {
    var key = String(severity || 'medium').toLowerCase();
    var label = SEVERITY_LABEL[key] || key;
    return '<span class="sev sev-' + esc(key) + '">' + esc(label) + '</span>';
  }

  function categoryLabel(category) {
    if (!category) return '未分类';
    return CATEGORY_LABEL[category] || category;
  }

  function fmtTs(ts) {
    if (!ts) return '—';
    var d = new Date(Number(ts) * 1000);
    if (isNaN(d.getTime())) return '—';
    var pad = function (n) {
      return String(n).padStart(2, '0');
    };
    return (
      d.getFullYear() +
      '-' +
      pad(d.getMonth() + 1) +
      '-' +
      pad(d.getDate()) +
      ' ' +
      pad(d.getHours()) +
      ':' +
      pad(d.getMinutes())
    );
  }

  function relative(ts) {
    if (!ts) return '—';
    var diff = Math.floor(Date.now() / 1000) - Number(ts);
    if (diff < 60) return '刚刚';
    if (diff < 3600) return Math.floor(diff / 60) + ' 分钟前';
    if (diff < 86400) return Math.floor(diff / 3600) + ' 小时前';
    return Math.floor(diff / 86400) + ' 天前';
  }

  function toast(message, options) {
    options = options || {};
    var root = $('#toast-root');
    if (!root) return;
    var el = document.createElement('div');
    el.className = 'toast' + (options.type === 'error' ? ' error' : '');
    el.innerHTML = '<span>' + esc(message) + '</span>';
    root.appendChild(el);
    setTimeout(function () {
      el.remove();
    }, options.duration || 3200);
  }

  function api(path, options) {
    options = options || {};
    var init = {
      method: options.method || 'GET',
      headers: { Accept: 'application/json' },
      credentials: 'same-origin'
    };
    if (options.body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(options.body);
    }
    return fetch(path, init).then(function (response) {
      if (response.status === 401 && path !== '/api/login') {
        showLogin('登录已过期，请重新登录');
        throw new Error('未登录');
      }
      return response
        .json()
        .catch(function () {
          return {};
        })
        .then(function (data) {
          if (!response.ok) {
            throw new Error(data && data.error ? data.error : '请求失败（' + response.status + '）');
          }
          return data;
        });
    });
  }

  /* ------------------------------------------------------------- 登录 */

  function showLogin(message) {
    $('#app-view').hidden = true;
    $('#auth-view').hidden = false;
    var error = $('#auth-error');
    if (message) {
      error.textContent = message;
      error.hidden = false;
    } else {
      error.hidden = true;
    }
    var input = $('#auth-password');
    if (input) input.focus();
  }

  function showApp() {
    $('#auth-view').hidden = true;
    $('#app-view').hidden = false;
  }

  $('#auth-form').addEventListener('submit', function (event) {
    event.preventDefault();
    var password = $('#auth-password').value;
    var submit = $('#auth-submit');
    submit.disabled = true;
    submit.textContent = '登录中…';
    api('/api/login', { method: 'POST', body: { password: password } })
      .then(function () {
        $('#auth-password').value = '';
        showApp();
        boot();
      })
      .catch(function (error) {
        $('#auth-error').textContent = error.message;
        $('#auth-error').hidden = false;
      })
      .finally(function () {
        submit.disabled = false;
        submit.textContent = '登录';
      });
  });

  var logoutBtn = $('#logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', function () {
      api('/api/logout', { method: 'POST' }).finally(function () {
        showLogin();
      });
    });
  }

  /* ------------------------------------------------------------- 路由 */

  function parseRoute() {
    var hash = (location.hash || '').replace(/^#\/?/, '');
    var name = hash.split('?')[0] || 'overview';
    return ROUTES[name] ? name : 'overview';
  }

  function renderRoute() {
    var name = parseRoute();
    state.route = name;
    var meta = ROUTES[name];
    $('#page-title').textContent = meta.title;
    $('#page-sub').textContent = meta.sub;
    Array.prototype.forEach.call(document.querySelectorAll('.nav-item'), function (item) {
      item.classList.toggle('active', item.dataset.route === name);
    });
    $('#view').innerHTML = '<div class="empty">加载中…</div>';
    meta.load().catch(function (error) {
      $('#view').innerHTML =
        '<div class="empty"><strong>加载失败</strong>' + esc(error.message) + '</div>';
    });
  }

  window.addEventListener('hashchange', renderRoute);

  /* ------------------------------------------------------------- 总览 */

  function loadOverview() {
    return api('/api/overview').then(function (data) {
      state.overview = data;
      var sev = data.by_severity || {};
      var stats = [
        { label: '告警总数', value: data.events, hint: '全部终端累计' },
        { label: '近 24 小时', value: data.events_24h, hint: '新增告警' },
        {
          label: '严重 / 高危',
          value: (sev.critical || 0) + (sev.high || 0),
          hint: '需要优先处理',
          cls: 'critical'
        },
        { label: '接入终端', value: data.agents, hint: '上报过数据的客户端' }
      ];
      var statHtml = stats
        .map(function (item) {
          return (
            '<div class="stat-card"><div class="stat-label">' +
            esc(item.label) +
            '</div><div class="stat-value ' +
            (item.cls || '') +
            '">' +
            num(item.value) +
            '</div><div class="stat-hint">' +
            esc(item.hint) +
            '</div></div>'
          );
        })
        .join('');

      var ingest = data.ingest || {};
      var cards =
        '<section class="card"><div class="card-head"><div><h2>接入概况</h2>' +
        '<div class="small muted" style="margin-top:2px">syslog 接收：报文 ' +
        num(ingest.packets) +
        ' · 入库 ' +
        num(ingest.accepted) +
        ' · 丢弃 ' +
        num(ingest.rejected) +
        '</div></div></div><div class="stat-grid">' +
        statHtml +
        '</div></section>';

      cards += categoryBars(data.by_category, '敏感数据类型分布');

      var rules = data.top_rules || [];
      cards +=
        '<section class="card"><div class="card-head"><div><h2>高频规则</h2>' +
        '<div class="small muted" style="margin-top:2px">命中次数最多的检测规则</div></div></div>' +
        (rules.length
          ? '<div class="table-wrap"><table class="grid"><thead><tr><th>规则</th><th>ID</th><th style="text-align:right">命中</th></tr></thead><tbody>' +
            rules
              .map(function (rule) {
                return (
                  '<tr><td>' +
                  esc(rule.rule_name || rule.rule_id) +
                  '</td><td class="cell-mono">' +
                  esc(rule.rule_id) +
                  '</td><td style="text-align:right">' +
                  num(rule.count) +
                  '</td></tr>'
                );
              })
              .join('') +
            '</tbody></table></div>'
          : '<div class="empty">暂无告警数据</div>') +
        '</section>';

      $('#view').innerHTML = cards;
      setNavCount(data.events);
      return data;
    });
  }

  function categoryBars(byCategory, title) {
    var entries = Object.keys(byCategory || {})
      .map(function (key) {
        return [key, Number(byCategory[key])];
      })
      .sort(function (a, b) {
        return b[1] - a[1];
      });
    var total = entries.reduce(function (sum, item) {
      return sum + item[1];
    }, 0);
    if (!entries.length) {
      return (
        '<section class="card"><div class="card-head"><div><h2>' +
        esc(title) +
        '</h2></div></div><div class="empty">暂无数据</div></section>'
      );
    }
    var max = entries[0][1] || 1;
    var rows = entries
      .map(function (item) {
        var pct = Math.max(2, Math.round((item[1] / max) * 100));
        return (
          '<div class="bar-row"><span class="bar-label">' +
          esc(categoryLabel(item[0])) +
          '</span><span class="bar-track"><span class="bar-fill" style="width:' +
          pct +
          '%"></span></span><span class="bar-value">' +
          num(item[1]) +
          '</span></div>'
        );
      })
      .join('');
    return (
      '<section class="card"><div class="card-head"><div><h2>' +
      esc(title) +
      '</h2><div class="small muted" style="margin-top:2px">共 ' +
      num(total) +
      ' 条告警</div></div></div><div class="bars">' +
      rows +
      '</div></section>'
    );
  }

  function setNavCount(count) {
    var el = $('#nav-count');
    if (!el) return;
    if (count > 0) {
      el.textContent = count > 999 ? '999+' : String(count);
      el.hidden = false;
    } else {
      el.hidden = true;
    }
  }

  /* ------------------------------------------------------------- 按用户 */

  function loadUsers() {
    return api('/api/users').then(function (data) {
      state.users = data.items || [];
      if (!state.users.length) {
        $('#view').innerHTML =
          '<div class="empty"><strong>还没有终端上报数据</strong>' +
          '在客户端配置 [syslog] enabled = true 并指向本服务端后，此处会显示按用户聚合的告警。</div>';
        return;
      }
      var rows = state.users
        .map(function (user) {
          var initial = (user.user || '?').slice(0, 1).toUpperCase();
          var cats = Object.keys(user.categories || {})
            .map(function (key) {
              return (
                '<span class="pill">' +
                esc(categoryLabel(key)) +
                ' ' +
                num(user.categories[key]) +
                '</span>'
              );
            })
            .join(' ');
          return (
            '<tr>' +
            '<td><div class="user-cell"><span class="avatar">' +
            esc(initial) +
            '</span><div><div><strong>' +
            esc(user.user) +
            '</strong></div><div class="cell-sub">' +
            esc(user.hostname) +
            ' · ' +
            num(user.agents) +
            ' 台终端</div></div></div></td>' +
            '<td>' +
            (user.critical ? '<span class="sev sev-critical">严重 ' + num(user.critical) + '</span> ' : '') +
            (user.high ? '<span class="sev sev-high">高危 ' + num(user.high) + '</span> ' : '') +
            (user.medium ? '<span class="sev sev-medium">中危 ' + num(user.medium) + '</span> ' : '') +
            (user.low ? '<span class="sev sev-low">低危 ' + num(user.low) + '</span>' : '') +
            '</td>' +
            '<td>' +
            (cats || '<span class="cell-sub">—</span>') +
            '</td>' +
            '<td style="text-align:right"><strong>' +
            num(user.events) +
            '</strong></td>' +
            '<td class="cell-sub">' +
            esc(relative(user.last_seen)) +
            '</td>' +
            '<td><button class="btn btn-sm" data-action="filter-user" data-user="' +
            esc(user.user) +
            '">查看明细</button></td>' +
            '</tr>'
          );
        })
        .join('');

      $('#view').innerHTML =
        '<section class="card"><div class="card-head"><div><h2>用户概览</h2>' +
        '<div class="small muted" style="margin-top:2px">按终端使用者聚合，共 ' +
        state.users.length +
        ' 个用户</div></div></div><div class="table-wrap"><table class="grid">' +
        '<thead><tr><th>用户</th><th>级别分布</th><th>敏感数据类型</th>' +
        '<th style="text-align:right">告警数</th><th>最近上报</th><th></th></tr></thead><tbody>' +
        rows +
        '</tbody></table></div></section>';
    });
  }

  /* ------------------------------------------------------------- 告警明细 */

  function loadEvents() {
    var params = [];
    if (state.filters.user) params.push('user=' + encodeURIComponent(state.filters.user));
    if (state.filters.category) params.push('category=' + encodeURIComponent(state.filters.category));
    if (state.filters.severity) params.push('severity=' + encodeURIComponent(state.filters.severity));
    if (state.filters.q) params.push('q=' + encodeURIComponent(state.filters.q));
    params.push('limit=' + state.pageSize);
    params.push('offset=' + state.page * state.pageSize);
    var query = params.join('&');

    return Promise.all([api('/api/events?' + query), loadFacets()]).then(function (results) {
      var data = results[0];
      state.events = data.items || [];
      state.eventsTotal = data.total || 0;
      $('#view').innerHTML = eventsHtml();
      bindFilterInputs();
    });
  }

  function loadFacets() {
    return api('/api/facets').then(function (data) {
      state.facets = data || state.facets;
      return data;
    });
  }

  function optionHtml(value, label, current) {
    return (
      '<option value="' +
      esc(value) +
      '"' +
      (String(value) === String(current) ? ' selected' : '') +
      '>' +
      esc(label) +
      '</option>'
    );
  }

  function eventsHtml() {
    var users = (state.facets.users || [])
      .map(function (user) {
        return optionHtml(user, user, state.filters.user);
      })
      .join('');
    var categories = (state.facets.categories || [])
      .map(function (category) {
        return optionHtml(category, categoryLabel(category), state.filters.category);
      })
      .join('');
    var severities = ['critical', 'high', 'medium', 'low']
      .map(function (severity) {
        return optionHtml(severity, SEVERITY_LABEL[severity], state.filters.severity);
      })
      .join('');

    var rows = state.events.length
      ? state.events
          .map(function (event) {
            return (
              '<tr>' +
              '<td class="cell-sub" style="white-space:nowrap">' +
              esc(relative(event.received_at)) +
              '<div class="cell-sub" style="font-size:11px">' +
              esc(fmtTs(event.received_at)) +
              '</div></td>' +
              '<td><strong>' +
              esc(event.username || event.hostname) +
              '</strong><div class="cell-sub">' +
              esc(event.hostname) +
              '</div></td>' +
              '<td>' +
              sevBadge(event.severity) +
              '</td>' +
              '<td><span class="pill">' +
              esc(categoryLabel(event.category)) +
              '</span></td>' +
              '<td>' +
              esc(event.rule_name || event.rule_id) +
              '<div class="rule-id">' +
              esc(event.rule_id) +
              '</div></td>' +
              '<td class="cell-mono">' +
              esc(event.masked || '—') +
              '</td>' +
              '<td class="cell-sub" style="max-width:280px">' +
              esc(event.snippet || event.path || '—') +
              '</td>' +
              '</tr>'
            );
          })
          .join('')
      : '<tr><td colspan="7"><div class="empty">没有符合条件的告警</div></td></tr>';

    var totalPages = Math.max(1, Math.ceil(state.eventsTotal / state.pageSize));
    var from = state.eventsTotal ? state.page * state.pageSize + 1 : 0;
    var to = Math.min(state.eventsTotal, (state.page + 1) * state.pageSize);

    return (
      '<section class="card"><div class="filters">' +
      '<select class="select" id="filter-user"><option value="">全部用户</option>' +
      users +
      '</select>' +
      '<select class="select" id="filter-category"><option value="">全部类型</option>' +
      categories +
      '</select>' +
      '<select class="select" id="filter-severity"><option value="">全部级别</option>' +
      severities +
      '</select>' +
      '<input class="input search" id="filter-q" type="search" placeholder="搜脱敏值 / 路径 / 上下文 / 主机" value="' +
      esc(state.filters.q) +
      '">' +
      '<span class="spacer"></span>' +
      '<button class="btn btn-sm" data-action="reset-filters">重置</button>' +
      '</div>' +
      '<div class="table-wrap"><table class="grid"><thead><tr>' +
      '<th>时间</th><th>用户 / 主机</th><th>级别</th><th>类型</th><th>规则</th>' +
      '<th>脱敏值</th><th>内容</th>' +
      '</tr></thead><tbody>' +
      rows +
      '</tbody></table></div>' +
      '<div class="pager"><span>共 ' +
      num(state.eventsTotal) +
      ' 条，当前 ' +
      from +
      '–' +
      to +
      '</span>' +
      '<button class="btn btn-sm" data-action="page-prev"' +
      (state.page <= 0 ? ' disabled' : '') +
      '>上一页</button>' +
      '<span>' +
      (state.page + 1) +
      ' / ' +
      totalPages +
      '</span>' +
      '<button class="btn btn-sm" data-action="page-next"' +
      (to >= state.eventsTotal ? ' disabled' : '') +
      '>下一页</button></div>' +
      '</section>'
    );
  }

  function bindFilterInputs() {
    var user = $('#filter-user');
    var category = $('#filter-category');
    var severity = $('#filter-severity');
    var q = $('#filter-q');
    if (user)
      user.addEventListener('change', function () {
        state.filters.user = user.value;
        state.page = 0;
        loadEvents().catch(showError);
      });
    if (category)
      category.addEventListener('change', function () {
        state.filters.category = category.value;
        state.page = 0;
        loadEvents().catch(showError);
      });
    if (severity)
      severity.addEventListener('change', function () {
        state.filters.severity = severity.value;
        state.page = 0;
        loadEvents().catch(showError);
      });
    if (q) {
      var timer = null;
      q.addEventListener('input', function () {
        clearTimeout(timer);
        timer = setTimeout(function () {
          state.filters.q = q.value.trim();
          state.page = 0;
          loadEvents()
            .then(function () {
              var input = $('#filter-q');
              if (input) {
                input.focus();
                input.setSelectionRange(input.value.length, input.value.length);
              }
            })
            .catch(showError);
        }, 260);
      });
    }
  }

  /* ------------------------------------------------------------- 规则 */

  function loadRules() {
    return api('/api/rules').then(function (data) {
      state.rules = data.current;
      state.builtin = data.builtin || [];
      return api('/api/rules/history').then(function (history) {
        state.history = history.items || [];
        $('#view').innerHTML = rulesHtml();
      });
    });
  }

  function rulesHtml() {
    var current = state.rules || {};
    var rules = current.rules || {};
    var disabled = rules.disabled || [];
    var custom = rules.custom || [];

    var builtinRows = state.builtin
      .map(function (rule) {
        var off = disabled.indexOf(rule.id) >= 0;
        return (
          '<div class="rule-card' +
          (off ? ' disabled' : '') +
          '">' +
          '<div class="rule-head">' +
          '<label class="switch"><input type="checkbox" data-builtin="' +
          esc(rule.id) +
          '"' +
          (off ? '' : ' checked') +
          '><span></span></label>' +
          '<strong>' +
          esc(rule.name) +
          '</strong>' +
          sevBadge(rule.severity) +
          '<span class="pill">' +
          esc(categoryLabel(rule.category)) +
          '</span>' +
          '<span class="rule-id">' +
          esc(rule.id) +
          '</span>' +
          '</div>' +
          '<div class="small muted">' +
          esc(rule.description || '') +
          '</div>' +
          '<div class="rule-pattern">' +
          esc(rule.pattern) +
          '</div>' +
          (rule.validators && rule.validators !== 'none'
            ? '<div class="small muted">校验器：<code>' + esc(rule.validators) + '</code></div>'
            : '') +
          '</div>'
        );
      })
      .join('');

    var customCards = custom.length
      ? custom
          .map(function (rule, index) {
            return (
              '<div class="rule-card"><div class="rule-head"><strong>' +
              esc(rule.name || rule.id) +
              '</strong>' +
              sevBadge(rule.severity) +
              '<span class="pill">' +
              esc(categoryLabel(rule.category)) +
              '</span>' +
              '<span class="rule-id">' +
              esc(rule.id) +
              '</span>' +
              '<span class="spacer"></span>' +
              '<button class="btn btn-sm" data-action="edit-rule" data-index="' +
              index +
              '">编辑</button>' +
              '<button class="btn btn-sm" data-action="delete-rule" data-index="' +
              index +
              '">删除</button>' +
              '</div>' +
              '<div class="small muted">' +
              esc(rule.description || '') +
              '</div>' +
              '<div class="rule-pattern">' +
              esc(rule.pattern) +
              '</div>' +
              '<div class="small muted">校验器：<code>' +
              esc(rule.validator || 'none') +
              '</code>' +
              (rule.keywords && rule.keywords.length
                ? ' · 关键词：' + esc(rule.keywords.join(', '))
                : '') +
              '</div></div>'
            );
          })
          .join('')
      : '<div class="empty">还没有自定义规则</div>';

    var historyRows = state.history
      .map(function (item) {
        return (
          '<tr><td class="cell-mono">v' +
          esc(item.revision) +
          '</td><td>' +
          esc(item.note || '—') +
          '</td><td>' +
          num(item.rule_count) +
          ' 条</td><td class="cell-sub">' +
          esc(fmtTs(item.updated_at)) +
          '</td><td><button class="btn btn-sm" data-action="rollback" data-revision="' +
          esc(item.revision) +
          '">回滚到此版本</button></td></tr>'
        );
      })
      .join('');

    return (
      '<section class="card"><div class="card-head"><div><h2>当前规则 v' +
      esc(current.revision || 0) +
      '</h2><div class="small muted" style="margin-top:2px">' +
      num(current.rule_count) +
      ' 条规则生效' +
      (current.note ? ' · ' + esc(current.note) : '') +
      ' · 发布后客户端下次拉取即生效</div></div>' +
      '<div style="display:flex;gap:8px">' +
      '<button class="btn btn-sm" data-action="add-rule">新增自定义规则</button>' +
      '<button class="btn btn-sm btn-primary" data-action="publish-rules">发布</button>' +
      '</div></div>' +
      '<div style="padding:16px;display:grid;gap:12px">' +
      builtinRows +
      '</div></section>' +
      '<section class="card"><div class="card-head"><div><h2>自定义规则</h2>' +
      '<div class="small muted" style="margin-top:2px">服务端下发后，所有客户端自动应用</div></div></div>' +
      '<div style="padding:16px;display:grid;gap:12px">' +
      customCards +
      '</div></section>' +
      '<section class="card"><div class="card-head"><div><h2>版本历史</h2>' +
      '<div class="small muted" style="margin-top:2px">回滚会生成新版本，历史不会被删除</div></div></div>' +
      (historyRows
        ? '<div class="table-wrap"><table class="grid"><thead><tr><th>版本</th><th>说明</th>' +
          '<th>规则数</th><th>发布时间</th><th></th></tr></thead><tbody>' +
          historyRows +
          '</tbody></table></div>'
        : '<div class="empty">尚无版本记录</div>') +
      '</section>'
    );
  }

  function currentRulesConfig() {
    var rules = (state.rules && state.rules.rules) || {};
    return {
      disabled: (rules.disabled || []).slice(),
      min_severity: rules.min_severity || 'low',
      custom: (rules.custom || []).slice()
    };
  }

  function publishRules(config, note) {
    return api('/api/rules', { method: 'POST', body: { rules: config, note: note || '' } })
      .then(function (result) {
        toast('已发布规则 v' + result.revision + '（' + result.rule_count + ' 条）');
        return loadRules();
      })
      .catch(function (error) {
        toast(error.message, { type: 'error', duration: 6000 });
      });
  }

  function ruleEditor(rule, index) {
    rule = rule || {
      id: '',
      name: '',
      category: 'internal',
      severity: 'medium',
      pattern: '',
      keywords: [],
      validator: 'none',
      description: '',
      context_chars: 160
    };
    var categories = Object.keys(CATEGORY_LABEL)
      .map(function (key) {
        return optionHtml(key, CATEGORY_LABEL[key], rule.category);
      })
      .join('');
    var severities = ['low', 'medium', 'high', 'critical']
      .map(function (key) {
        return optionHtml(key, SEVERITY_LABEL[key], rule.severity);
      })
      .join('');

    openModal(
      '<div class="modal" style="width:620px"><div class="modal-head"><h3>' +
        (index == null ? '新增自定义规则' : '编辑自定义规则') +
        '</h3><span class="spacer"></span>' +
        '<button class="icon-btn" data-action="close-modal">✕</button></div>' +
        '<div class="modal-body"><div class="rule-form">' +
        '<div class="row2"><label class="field"><span>规则 ID</span>' +
        '<input class="input" id="rule-id" value="' +
        esc(rule.id) +
        '"' +
        (index == null ? '' : ' readonly') +
        '></label>' +
        '<label class="field"><span>名称</span><input class="input" id="rule-name" value="' +
        esc(rule.name) +
        '"></label></div>' +
        '<div class="row2"><label class="field"><span>类型</span>' +
        '<select class="select" id="rule-category">' +
        categories +
        '</select></label>' +
        '<label class="field"><span>级别</span><select class="select" id="rule-severity">' +
        severities +
        '</select></label></div>' +
        '<label class="field"><span>正则（Rust regex，第一个捕获组为敏感值）</span>' +
        '<textarea class="input" id="rule-pattern">' +
        esc(rule.pattern) +
        '</textarea></label>' +
        '<label class="field"><span>关键词（可选，逗号分隔，命中附近需出现）</span>' +
        '<input class="input" id="rule-keywords" value="' +
        esc((rule.keywords || []).join(', ')) +
        '"></label>' +
        '<div class="row2"><label class="field"><span>校验器</span>' +
        '<input class="input" id="rule-validator" value="' +
        esc(rule.validator || 'none') +
        '" placeholder="none / luhn / bank_card / cn_id / phone ...">' +
        '</label>' +
        '<label class="field"><span>上下文长度</span>' +
        '<input class="input" type="number" id="rule-context" value="' +
        Number(rule.context_chars || 160) +
        '"></label></div>' +
        '<label class="field"><span>说明</span><input class="input" id="rule-description" value="' +
        esc(rule.description || '') +
        '"></label>' +
        '</div></div>' +
        '<div class="modal-foot"><button class="btn" data-action="close-modal">取消</button>' +
        '<button class="btn btn-primary" data-action="save-rule" data-index="' +
        (index == null ? '' : index) +
        '">保存</button></div></div>'
    );
  }

  function readRuleForm() {
    return {
      id: ($('#rule-id') || {}).value.trim(),
      name: ($('#rule-name') || {}).value.trim(),
      category: ($('#rule-category') || {}).value,
      severity: ($('#rule-severity') || {}).value,
      pattern: ($('#rule-pattern') || {}).value.trim(),
      keywords: ($('#rule-keywords') || {})
        .value.split(',')
        .map(function (item) {
          return item.trim();
        })
        .filter(Boolean),
      validator: ($('#rule-validator') || {}).value.trim() || 'none',
      context_chars: Number(($('#rule-context') || {}).value || 160),
      description: ($('#rule-description') || {}).value.trim()
    };
  }

  /* ------------------------------------------------------------- 终端 */

  function loadAgents() {
    return Promise.all([api('/api/agents'), api('/api/rules/sync')]).then(function (results) {
      state.agents = results[0].items || [];
      state.sync = results[1];
      $('#view').innerHTML = agentsHtml();
    });
  }

  function agentsHtml() {
    var latest = (state.sync && state.sync.latest_revision) || 0;
    var byAgent = {};
    ((state.sync && state.sync.agents) || []).forEach(function (item) {
      byAgent[item.agent_id] = item.applied_revision;
    });

    var rows = state.agents.length
      ? state.agents
          .map(function (agent) {
            var applied = byAgent[agent.id] || 0;
            var inSync = applied >= latest;
            return (
              '<tr><td><strong>' +
              esc(agent.hostname) +
              '</strong><div class="cell-sub">' +
              esc(agent.id.slice(0, 12)) +
              '…</div></td>' +
              '<td>' +
              (agent.username ? esc(agent.username) : '<span class="cell-sub">—</span>') +
              '</td>' +
              '<td class="cell-sub">' +
              esc(agent.platform || '—') +
              '</td>' +
              '<td class="cell-sub">' +
              esc(agent.version || '—') +
              '</td>' +
              '<td>' +
              (inSync
                ? '<span class="pill ok">已同步 v' + applied + '</span>'
                : '<span class="pill warn">v' + applied + ' / 最新 v' + latest + '</span>') +
              '</td>' +
              '<td class="cell-sub">' +
              esc(relative(agent.last_seen)) +
              '<div style="font-size:11px">' +
              esc(agent.remote_addr || '') +
              '</div></td>' +
              '<td><button class="btn btn-sm" data-action="delete-agent" data-agent="' +
              esc(agent.id) +
              '" data-host="' +
              esc(agent.hostname) +
              '">移除</button></td></tr>'
            );
          })
          .join('')
      : '<tr><td colspan="7"><div class="empty">还没有终端接入</div></td></tr>';

    return (
      '<section class="card"><div class="card-head"><div><h2>已接入终端</h2>' +
      '<div class="small muted" style="margin-top:2px">共 ' +
      state.agents.length +
      ' 台，' +
      ((state.sync && state.sync.up_to_date) || 0) +
      ' 台已应用最新规则 v' +
      latest +
      '</div></div></div><div class="table-wrap"><table class="grid">' +
      '<thead><tr><th>主机</th><th>用户</th><th>平台</th><th>客户端版本</th>' +
      '<th>规则同步</th><th>最近上报</th><th></th></tr></thead><tbody>' +
      rows +
      '</tbody></table></div></section>'
    );
  }

  /* ------------------------------------------------------------- 设置 */

  function loadSettings() {
    return Promise.all([api('/api/config'), api('/api/audit')]).then(function (results) {
      state.config = results[0];
      state.audit = results[1].items || [];
      $('#view').innerHTML = settingsHtml();
    });
  }

  function settingsHtml() {
    var config = state.config || {};
    var ingest = config.ingest || {};
    var auditRows = state.audit.length
      ? state.audit
          .map(function (item) {
            return (
              '<tr><td class="cell-sub">' +
              esc(fmtTs(item.at)) +
              '</td><td>' +
              esc(item.actor) +
              '</td><td class="cell-mono">' +
              esc(item.action) +
              '</td><td class="cell-sub">' +
              esc(item.detail) +
              '</td></tr>'
            );
          })
          .join('')
      : '<tr><td colspan="4"><div class="empty">暂无审计记录</div></td></tr>';

    return (
      '<section class="card"><div class="card-head"><div><h2>syslog 接收</h2>' +
      '<div class="small muted" style="margin-top:2px">修改需编辑 server.toml 并重启</div></div></div>' +
      '<div class="stat-grid">' +
      '<div class="stat-card"><div class="stat-label">状态</div><div class="stat-value" style="font-size:18px">' +
      (ingest.enabled ? '已启用' : '已关闭') +
      '</div><div class="stat-hint">' +
      esc(ingest.protocol || '—') +
      '</div></div>' +
      '<div class="stat-card"><div class="stat-label">监听地址</div>' +
      '<div class="cell-mono" style="margin-top:6px">' +
      esc(ingest.bind || '—') +
      '</div></div>' +
      '<div class="stat-card"><div class="stat-label">来源白名单</div>' +
      '<div class="stat-value" style="font-size:18px">' +
      ((ingest.allow_cidrs || []).length || '不限') +
      '</div><div class="stat-hint">' +
      esc(((ingest.allow_cidrs || []).join(', ') || '未配置')) +
      '</div></div>' +
      '<div class="stat-card"><div class="stat-label">告警保留</div>' +
      '<div class="stat-value" style="font-size:18px">' +
      (config.retention_days || 0) +
      ' 天</div><div class="stat-hint">0 表示永久保留</div></div>' +
      '</div></section>' +
      '<section class="card"><div class="card-head"><div><h2>接入地址</h2>' +
      '<div class="small muted" style="margin-top:2px">客户端两种接入方式：mDNS 自动发现，或手填静态地址</div></div></div>' +
      '<div class="stat-grid">' +
      '<div class="stat-card"><div class="stat-label">控制台</div>' +
      '<div class="cell-mono" style="margin-top:6px">' +
      esc((config.tls ? 'https://' : 'http://') + (location.host || config.console_bind || '—')) +
      '</div><div class="stat-hint">' +
      (config.tls ? '已启用 HTTPS' : '明文 HTTP（建议配置 [tls]）') +
      ' · 监听 ' +
      esc(config.console_bind || '—') +
      '</div></div>' +
      '<div class="stat-card"><div class="stat-label">mDNS 广播</div>' +
      '<div class="stat-value" style="font-size:18px">' +
      (config.discover && config.discover.enabled
        ? (ingest.enabled ? '已启用' : '已跳过')
        : '已关闭') +
      '</div><div class="stat-hint">' +
      (config.discover && config.discover.enabled && !ingest.enabled
        ? 'syslog 接收已关闭，无地址可广播'
        : esc((config.discover && config.discover.service) || '—')) +
      '</div></div>' +
      '<div class="stat-card"><div class="stat-label">广播实例名</div>' +
      '<div class="cell-mono" style="margin-top:6px">' +
      esc((config.discover && config.discover.instance) || '—') +
      '</div></div>' +
      '</div></section>' +
      '<section class="card"><div class="card-head"><div><h2>客户端接入方式</h2>' +
      '<div class="small muted" style="margin-top:2px">发现本服务端：sentinel syslog discover</div></div></div>' +
      '<div style="padding:16px"><div class="rule-pattern">' +
      esc(
        '[syslog]\nenabled = true\ndiscovery = "mdns"   # 或填 discovery = "static" 并指定 server\nserver = "<本服务端地址>:5514"'
      ) +
      '</div><div class="small muted" style="margin-top:10px">' +
      '客户端拉取规则：GET /api/agent/rules（Authorization: Bearer &lt;Agent Token&gt;）' +
      '</div></div></section>' +
      '<section class="card"><div class="card-head"><div><h2>数据维护</h2>' +
      '<div class="small muted" style="margin-top:2px">清理不可恢复，请谨慎操作</div></div>' +
      '<button class="btn btn-sm" data-action="purge">清理过期告警</button></div>' +
      '<div class="empty">按 config 中的保留天数删除历史告警</div></section>' +
      '<section class="card"><div class="card-head"><div><h2>审计日志</h2>' +
      '<div class="small muted" style="margin-top:2px">规则发布、回滚、清理等管理操作</div></div></div>' +
      '<div class="table-wrap"><table class="grid"><thead><tr><th>时间</th><th>操作者</th>' +
      '<th>动作</th><th>详情</th></tr></thead><tbody>' +
      auditRows +
      '</tbody></table></div></section>'
    );
  }

  /* ------------------------------------------------------------- 弹窗 */

  var modalStack = [];

  function openModal(html) {
    modalStack.push(html);
    renderModal();
  }

  function closeModal() {
    modalStack.pop();
    renderModal();
  }

  function renderModal() {
    var root = $('#modal-root');
    if (!root) return;
    if (!modalStack.length) {
      root.innerHTML = '';
      return;
    }
    root.innerHTML = '<div class="modal-backdrop">' + modalStack[modalStack.length - 1] + '</div>';
  }

  function confirmDialog(title, message, onConfirm) {
    openModal(
      '<div class="modal" style="width:440px"><div class="modal-head"><h3>' +
        esc(title) +
        '</h3><span class="spacer"></span>' +
        '<button class="icon-btn" data-action="close-modal">✕</button></div>' +
        '<div class="modal-body"><p class="small" style="color:var(--text-2);line-height:1.7">' +
        esc(message) +
        '</p></div><div class="modal-foot">' +
        '<button class="btn" data-action="close-modal">取消</button>' +
        '<button class="btn btn-primary" data-action="confirm-ok">确认</button></div></div>'
    );
    window.__pendingConfirm = onConfirm;
  }

  function showError(error) {
    toast(error && error.message ? error.message : String(error), { type: 'error' });
  }

  /* ------------------------------------------------------------- 事件 */

  document.addEventListener('click', function (event) {
    var actionEl = event.target.closest('[data-action]');
    if (!actionEl) {
      if (event.target.classList && event.target.classList.contains('modal-backdrop')) closeModal();
      return;
    }
    var action = actionEl.dataset.action;

    switch (action) {
      case 'close-modal':
        closeModal();
        break;
      case 'confirm-ok': {
        var callback = window.__pendingConfirm;
        window.__pendingConfirm = null;
        closeModal();
        if (callback) callback();
        break;
      }
      case 'filter-user':
        state.filters.user = actionEl.dataset.user || '';
        state.page = 0;
        location.hash = '#/events';
        break;
      case 'reset-filters':
        state.filters = { user: '', category: '', severity: '', q: '' };
        state.page = 0;
        loadEvents().catch(showError);
        break;
      case 'page-prev':
        if (state.page > 0) {
          state.page -= 1;
          loadEvents().catch(showError);
        }
        break;
      case 'page-next':
        if ((state.page + 1) * state.pageSize < state.eventsTotal) {
          state.page += 1;
          loadEvents().catch(showError);
        }
        break;
      case 'add-rule':
        ruleEditor(null, null);
        break;
      case 'edit-rule': {
        var index = Number(actionEl.dataset.index);
        var list = currentRulesConfig().custom;
        ruleEditor(list[index], index);
        break;
      }
      case 'delete-rule': {
        var delIndex = Number(actionEl.dataset.index);
        var current = currentRulesConfig();
        var target = current.custom[delIndex];
        if (!target) break;
        confirmDialog('删除规则？', '将从下发规则中移除「' + target.name + '」，发布后客户端不再检测该项。', function () {
          current.custom.splice(delIndex, 1);
          publishRules(current, '删除规则 ' + target.id);
        });
        break;
      }
      case 'save-rule': {
        var rule = readRuleForm();
        if (!rule.id || !rule.name || !rule.pattern) {
          toast('规则 ID、名称、正则均不能为空', { type: 'error' });
          break;
        }
        var config = currentRulesConfig();
        var editIndex = actionEl.dataset.index;
        if (editIndex === '') {
          if (config.custom.some(function (item) {
            return item.id === rule.id;
          })) {
            toast('规则 ID 已存在', { type: 'error' });
            break;
          }
          config.custom.push(rule);
        } else {
          config.custom[Number(editIndex)] = rule;
        }
        closeModal();
        publishRules(config, '保存规则 ' + rule.id);
        break;
      }
      case 'publish-rules':
        publishRules(currentRulesConfig(), '手动发布');
        break;
      case 'rollback': {
        var revision = Number(actionEl.dataset.revision);
        confirmDialog('回滚规则？', '将把 v' + revision + ' 的内容作为新版本发布，客户端随后同步。', function () {
          api('/api/rules/rollback', { method: 'POST', body: { revision: revision } })
            .then(function (result) {
              toast('已回滚，新版本 v' + result.revision);
              return loadRules();
            })
            .catch(showError);
        });
        break;
      }
      case 'delete-agent': {
        var agentId = actionEl.dataset.agent;
        var host = actionEl.dataset.host;
        confirmDialog('移除终端？', '将删除「' + host + '」及其全部告警记录。', function () {
          api('/api/agents?id=' + encodeURIComponent(agentId), { method: 'DELETE' })
            .then(function () {
              toast('已移除');
              return loadAgents();
            })
            .catch(showError);
        });
        break;
      }
      case 'purge':
        confirmDialog('清理过期告警？', '按配置的保留天数删除历史告警，操作不可恢复。', function () {
          api('/api/purge', { method: 'POST', body: {} })
            .then(function (result) {
              toast('已清理 ' + result.removed + ' 条');
              return loadSettings();
            })
            .catch(showError);
        });
        break;
      default:
        break;
    }
  });

  /* 内置规则开关：勾选状态即 enabled，取反写入 disabled 列表后立即发布。 */
  document.addEventListener('change', function (event) {
    var toggle = event.target.closest('[data-builtin]');
    if (!toggle) return;
    var id = toggle.dataset.builtin;
    var config = currentRulesConfig();
    var index = config.disabled.indexOf(id);
    if (toggle.checked) {
      if (index >= 0) config.disabled.splice(index, 1);
    } else if (index < 0) {
      config.disabled.push(id);
    }
    publishRules(config, (toggle.checked ? '启用 ' : '停用 ') + id);
  });

  /* ------------------------------------------------------------- 启动 */

  function boot() {
    renderRoute();
    setInterval(function () {
      if (state.route === 'overview') {
        loadOverview().catch(function () {});
      }
    }, 30000);
  }

  api('/api/me')
    .then(function (me) {
      state.me = me;
      showApp();
      boot();
    })
    .catch(function () {
      showLogin();
    });
})();
