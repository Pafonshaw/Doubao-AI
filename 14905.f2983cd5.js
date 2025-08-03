(self.__LOADABLE_LOADED_CHUNKS__ = self.__LOADABLE_LOADED_CHUNKS__ || []).push([
  ["14905"],
  {
    121412: function (e) {
      var t, r;
      "undefined" != typeof self && self,
        (r = function () {
          return ((e) => {
            var t = {};
            function r(i) {
              var n;
              return (
                t[i] ||
                ((n = t[i] = { i: i, l: !1, exports: {} }),
                e[i].call(n.exports, n, n.exports, r),
                (n.l = !0),
                n)
              ).exports;
            }
            return (
              (r.m = e),
              (r.c = t),
              (r.d = function (e, t, i) {
                r.o(e, t) ||
                  Object.defineProperty(e, t, { enumerable: !0, get: i });
              }),
              (r.r = function (e) {
                "undefined" != typeof Symbol &&
                  Symbol.toStringTag &&
                  Object.defineProperty(e, Symbol.toStringTag, {
                    value: "Module",
                  }),
                  Object.defineProperty(e, "__esModule", { value: !0 });
              }),
              (r.t = function (e, t) {
                if (
                  (1 & t && (e = r(e)),
                  8 & t || (4 & t && "object" == typeof e && e && e.__esModule))
                )
                  return e;
                var i = Object.create(null);
                if (
                  (r.r(i),
                  Object.defineProperty(i, "default", {
                    enumerable: !0,
                    value: e,
                  }),
                  2 & t && "string" != typeof e)
                )
                  for (var n in e)
                    r.d(
                      i,
                      n,
                      function (t) {
                        return e[t];
                      }.bind(null, n)
                    );
                return i;
              }),
              (r.n = function (e) {
                var t =
                  e && e.__esModule
                    ? function () {
                        return e.default;
                      }
                    : function () {
                        return e;
                      };
                return r.d(t, "a", t), t;
              }),
              (r.o = function (e, t) {
                return Object.prototype.hasOwnProperty.call(e, t);
              }),
              (r.p = ""),
              r((r.s = 11))
            );
          })([
            function (e, t, r) {
              var i = "object" == typeof Reflect ? Reflect : null,
                n =
                  i && "function" == typeof i.apply
                    ? i.apply
                    : function (e, t, r) {
                        return Function.prototype.apply.call(e, t, r);
                      },
                o =
                  i && "function" == typeof i.ownKeys
                    ? i.ownKeys
                    : Object.getOwnPropertySymbols
                    ? function (e) {
                        return Object.getOwnPropertyNames(e).concat(
                          Object.getOwnPropertySymbols(e)
                        );
                      }
                    : function (e) {
                        return Object.getOwnPropertyNames(e);
                      },
                s =
                  Number.isNaN ||
                  function (e) {
                    return e != e;
                  };
              function a() {
                a.init.call(this);
              }
              (e.exports = a),
                (e.exports.once = function (e, t) {
                  return new Promise(function (r, i) {
                    var n;
                    function o(r) {
                      e.removeListener(t, s), i(r);
                    }
                    function s() {
                      "function" == typeof e.removeListener &&
                        e.removeListener("error", o),
                        r([].slice.call(arguments));
                    }
                    m(e, t, s, { once: !0 }),
                      "error" !== t &&
                        ((n = { once: !0 }),
                        "function" == typeof e.on && m(e, "error", o, n));
                  });
                }),
                ((a.EventEmitter = a).prototype._events = void 0),
                (a.prototype._eventsCount = 0),
                (a.prototype._maxListeners = void 0);
              var c = 10;
              function u(e) {
                if ("function" != typeof e)
                  throw TypeError(
                    'The "listener" argument must be of type Function. Received type ' +
                      typeof e
                  );
              }
              function l(e) {
                return void 0 === e._maxListeners
                  ? a.defaultMaxListeners
                  : e._maxListeners;
              }
              function f(e, t, r, i) {
                var n, o;
                return (
                  u(r),
                  void 0 === (n = e._events)
                    ? ((n = e._events = Object.create(null)),
                      (e._eventsCount = 0))
                    : (void 0 !== n.newListener &&
                        (e.emit("newListener", t, r.listener || r),
                        (n = e._events)),
                      (o = n[t])),
                  void 0 === o
                    ? ((o = n[t] = r), ++e._eventsCount)
                    : ("function" == typeof o
                        ? (o = n[t] = i ? [r, o] : [o, r])
                        : i
                        ? o.unshift(r)
                        : o.push(r),
                      0 < (n = l(e)) &&
                        o.length > n &&
                        !o.warned &&
                        ((o.warned = !0),
                        ((i = Error(
                          "Possible EventEmitter memory leak detected. " +
                            o.length +
                            " " +
                            String(t) +
                            " listeners added. Use emitter.setMaxListeners() to increase limit"
                        )).name = "MaxListenersExceededWarning"),
                        (i.emitter = e),
                        (i.type = t),
                        (i.count = o.length),
                        console)),
                  e
                );
              }
              function h(e, t, r) {
                return (
                  ((t = function () {
                    if (!this.fired)
                      return (
                        this.target.removeListener(this.type, this.wrapFn),
                        (this.fired = !0),
                        0 == arguments.length
                          ? this.listener.call(this.target)
                          : this.listener.apply(this.target, arguments)
                      );
                  }.bind(
                    (e = {
                      fired: !1,
                      wrapFn: void 0,
                      target: e,
                      type: t,
                      listener: r,
                    })
                  )).listener = r),
                  (e.wrapFn = t)
                );
              }
              function d(e, t, r) {
                var e = e._events;
                return void 0 === e || void 0 === (e = e[t])
                  ? []
                  : "function" == typeof e
                  ? r
                    ? [e.listener || e]
                    : [e]
                  : r
                  ? (function (e) {
                      for (var t = Array(e.length), r = 0; r < t.length; ++r)
                        t[r] = e[r].listener || e[r];
                      return t;
                    })(e)
                  : g(e, e.length);
              }
              function p(e) {
                var t = this._events;
                if (void 0 !== t) {
                  if ("function" == typeof (t = t[e])) return 1;
                  if (void 0 !== t) return t.length;
                }
                return 0;
              }
              function g(e, t) {
                for (var r = Array(t), i = 0; i < t; ++i) r[i] = e[i];
                return r;
              }
              function m(e, t, r, i) {
                if ("function" == typeof e.on)
                  i.once ? e.once(t, r) : e.on(t, r);
                else {
                  if ("function" != typeof e.addEventListener)
                    throw TypeError(
                      'The "emitter" argument must be of type EventEmitter. Received type ' +
                        typeof e
                    );
                  e.addEventListener(t, function n(o) {
                    i.once && e.removeEventListener(t, n), r(o);
                  });
                }
              }
              Object.defineProperty(a, "defaultMaxListeners", {
                enumerable: !0,
                get: function () {
                  return c;
                },
                set: function (e) {
                  if ("number" != typeof e || e < 0 || s(e))
                    throw RangeError(
                      'The value of "defaultMaxListeners" is out of range. It must be a non-negative number. Received ' +
                        e +
                        "."
                    );
                  c = e;
                },
              }),
                (a.init = function () {
                  (void 0 !== this._events &&
                    this._events !== Object.getPrototypeOf(this)._events) ||
                    ((this._events = Object.create(null)),
                    (this._eventsCount = 0)),
                    (this._maxListeners = this._maxListeners || void 0);
                }),
                (a.prototype.setMaxListeners = function (e) {
                  if ("number" != typeof e || e < 0 || s(e))
                    throw RangeError(
                      'The value of "n" is out of range. It must be a non-negative number. Received ' +
                        e +
                        "."
                    );
                  return (this._maxListeners = e), this;
                }),
                (a.prototype.getMaxListeners = function () {
                  return l(this);
                }),
                (a.prototype.emit = function (e) {
                  for (var t = [], r = 1; r < arguments.length; r++)
                    t.push(arguments[r]);
                  var i = "error" === e,
                    o = this._events;
                  if (void 0 !== o) i = i && void 0 === o.error;
                  else if (!i) return !1;
                  if (i) {
                    if ((s = 0 < t.length ? t[0] : s) instanceof Error) throw s;
                    throw (
                      (((i = Error(
                        "Unhandled error." + (s ? " (" + s.message + ")" : "")
                      )).context = s),
                      i)
                    );
                  }
                  var s = o[e];
                  if (void 0 === s) return !1;
                  if ("function" == typeof s) n(s, this, t);
                  else
                    for (var a = s.length, c = g(s, a), r = 0; r < a; ++r)
                      n(c[r], this, t);
                  return !0;
                }),
                (a.prototype.on = a.prototype.addListener =
                  function (e, t) {
                    return f(this, e, t, !1);
                  }),
                (a.prototype.prependListener = function (e, t) {
                  return f(this, e, t, !0);
                }),
                (a.prototype.once = function (e, t) {
                  return u(t), this.on(e, h(this, e, t)), this;
                }),
                (a.prototype.prependOnceListener = function (e, t) {
                  return u(t), this.prependListener(e, h(this, e, t)), this;
                }),
                (a.prototype.off = a.prototype.removeListener =
                  function (e, t) {
                    var r, i, n, o, s;
                    if (
                      (u(t),
                      void 0 !== (i = this._events) && void 0 !== (r = i[e]))
                    ) {
                      if (r === t || r.listener === t)
                        0 == --this._eventsCount
                          ? (this._events = Object.create(null))
                          : (delete i[e],
                            i.removeListener &&
                              this.emit("removeListener", e, r.listener || t));
                      else if ("function" != typeof r) {
                        for (n = -1, o = r.length - 1; 0 <= o; o--)
                          if (r[o] === t || r[o].listener === t) {
                            (s = r[o].listener), (n = o);
                            break;
                          }
                        if (n < 0) return this;
                        0 === n
                          ? r.shift()
                          : (function (e, t) {
                              for (; t + 1 < e.length; t++) e[t] = e[t + 1];
                              e.pop();
                            })(r, n),
                          1 === r.length && (i[e] = r[0]),
                          void 0 !== i.removeListener &&
                            this.emit("removeListener", e, s || t);
                      }
                    }
                    return this;
                  }),
                (a.prototype.removeAllListeners = function (e) {
                  var t,
                    r = this._events;
                  if (void 0 !== r) {
                    if (void 0 === r.removeListener)
                      0 == arguments.length
                        ? ((this._events = Object.create(null)),
                          (this._eventsCount = 0))
                        : void 0 !== r[e] &&
                          (0 == --this._eventsCount
                            ? (this._events = Object.create(null))
                            : delete r[e]);
                    else if (0 == arguments.length) {
                      for (var i, n = Object.keys(r), o = 0; o < n.length; ++o)
                        "removeListener" !== (i = n[o]) &&
                          this.removeAllListeners(i);
                      this.removeAllListeners("removeListener"),
                        (this._events = Object.create(null)),
                        (this._eventsCount = 0);
                    } else if ("function" == typeof (t = r[e]))
                      this.removeListener(e, t);
                    else if (void 0 !== t)
                      for (o = t.length - 1; 0 <= o; o--)
                        this.removeListener(e, t[o]);
                  }
                  return this;
                }),
                (a.prototype.listeners = function (e) {
                  return d(this, e, !0);
                }),
                (a.prototype.rawListeners = function (e) {
                  return d(this, e, !1);
                }),
                (a.listenerCount = function (e, t) {
                  return "function" == typeof e.listenerCount
                    ? e.listenerCount(t)
                    : p.call(e, t);
                }),
                (a.prototype.listenerCount = p),
                (a.prototype.eventNames = function () {
                  return 0 < this._eventsCount ? o(this._events) : [];
                });
            },
            function (e, t, r) {
              (function (t) {
                e.exports = ((e) => {
                  var r =
                      e && "object" == typeof e && "default" in e
                        ? e
                        : { default: e },
                    i =
                      "undefined" != typeof globalThis
                        ? globalThis
                        : "undefined" != typeof window
                        ? window
                        : void 0 !== t
                        ? t
                        : "undefined" != typeof self
                        ? self
                        : {};
                  function n(e, t, r) {
                    return (
                      e(
                        (r = {
                          path: t,
                          exports: {},
                          require: function (e, t) {
                            return (function () {
                              throw Error(
                                "Dynamic requires are not currently supported by @rollup/plugin-commonjs"
                              );
                            })(null == t && r.path);
                          },
                        }),
                        r.exports
                      ),
                      r.exports
                    );
                  }
                  function o(e) {
                    try {
                      return encodeURIComponent(e)
                        .replace(/[^A-Za-z0-9_.~\-%]+/g, escape)
                        .replace(/[*]/g, function (e) {
                          return "%".concat(
                            e.charCodeAt(0).toString(16).toUpperCase()
                          );
                        });
                    } catch (e) {
                      return "";
                    }
                  }
                  function s(e) {
                    return Object.keys(e)
                      .sort()
                      .map(function (t) {
                        var r = e[t];
                        if (null != r && (t = o(t)))
                          return Array.isArray(r)
                            ? ""
                                .concat(t, "=")
                                .concat(
                                  r.map(o).sort().join("&".concat(t, "="))
                                )
                            : "".concat(t, "=").concat(o(r));
                      })
                      .filter(function (e) {
                        return e;
                      })
                      .join("&");
                  }
                  var a = n(function (e, t) {
                      e.exports = ((e) => {
                        if (
                          ("undefined" != typeof window &&
                            window.crypto &&
                            (t = window.crypto),
                          "undefined" != typeof self &&
                            self.crypto &&
                            (t = self.crypto),
                          !(t =
                            (t =
                              (t =
                                "undefined" != typeof globalThis &&
                                globalThis.crypto
                                  ? globalThis.crypto
                                  : t) ||
                              "undefined" == typeof window ||
                              !window.msCrypto
                                ? t
                                : window.msCrypto) ||
                            void 0 === i ||
                            !i.crypto
                              ? t
                              : i.crypto))
                        )
                          try {
                            t = r.default;
                          } catch (e) {}
                        var t,
                          n =
                            Object.create ||
                            (() => {
                              function e() {}
                              return function (t) {
                                return (
                                  (e.prototype = t),
                                  (t = new e()),
                                  (e.prototype = null),
                                  t
                                );
                              };
                            })(),
                          o = {},
                          s = (o.lib = {}),
                          a = (s.Base = {
                            extend: function (e) {
                              var t = n(this);
                              return (
                                e && t.mixIn(e),
                                (t.hasOwnProperty("init") &&
                                  this.init !== t.init) ||
                                  (t.init = function () {
                                    t.$super.init.apply(this, arguments);
                                  }),
                                ((t.init.prototype = t).$super = this),
                                t
                              );
                            },
                            create: function () {
                              var e = this.extend();
                              return e.init.apply(e, arguments), e;
                            },
                            init: function () {},
                            mixIn: function (e) {
                              for (var t in e)
                                e.hasOwnProperty(t) && (this[t] = e[t]);
                              e.hasOwnProperty("toString") &&
                                (this.toString = e.toString);
                            },
                            clone: function () {
                              return this.init.prototype.extend(this);
                            },
                          }),
                          c = (s.WordArray = a.extend({
                            init: function (e, t) {
                              (e = this.words = e || []),
                                (this.sigBytes = null != t ? t : 4 * e.length);
                            },
                            toString: function (e) {
                              return (e || l).stringify(this);
                            },
                            concat: function (e) {
                              var t = this.words,
                                r = e.words,
                                i = this.sigBytes,
                                n = e.sigBytes;
                              if ((this.clamp(), i % 4))
                                for (var o = 0; o < n; o++) {
                                  var s =
                                    (r[o >>> 2] >>> (24 - (o % 4) * 8)) & 255;
                                  t[(i + o) >>> 2] |=
                                    s << (24 - ((i + o) % 4) * 8);
                                }
                              else
                                for (var a = 0; a < n; a += 4)
                                  t[(i + a) >>> 2] = r[a >>> 2];
                              return (this.sigBytes += n), this;
                            },
                            clamp: function () {
                              var t = this.words,
                                r = this.sigBytes;
                              (t[r >>> 2] &= 0xffffffff << (32 - (r % 4) * 8)),
                                (t.length = e.ceil(r / 4));
                            },
                            clone: function () {
                              var e = a.clone.call(this);
                              return (e.words = this.words.slice(0)), e;
                            },
                            random: function (e) {
                              for (var r = [], i = 0; i < e; i += 4)
                                r.push(
                                  (() => {
                                    if (t) {
                                      if (
                                        "function" == typeof t.getRandomValues
                                      )
                                        try {
                                          return t.getRandomValues(
                                            new Uint32Array(1)
                                          )[0];
                                        } catch (e) {}
                                      if ("function" == typeof t.randomBytes)
                                        try {
                                          return t.randomBytes(4).readInt32LE();
                                        } catch (e) {}
                                    }
                                    throw Error(
                                      "Native crypto module could not be used to get secure random number."
                                    );
                                  })()
                                );
                              return new c.init(r, e);
                            },
                          })),
                          u = (o.enc = {}),
                          l = (u.Hex = {
                            stringify: function (e) {
                              for (
                                var t = e.words, r = e.sigBytes, i = [], n = 0;
                                n < r;
                                n++
                              ) {
                                var o =
                                  (t[n >>> 2] >>> (24 - (n % 4) * 8)) & 255;
                                i.push((o >>> 4).toString(16)),
                                  i.push((15 & o).toString(16));
                              }
                              return i.join("");
                            },
                            parse: function (e) {
                              for (
                                var t = e.length, r = [], i = 0;
                                i < t;
                                i += 2
                              )
                                r[i >>> 3] |=
                                  parseInt(e.substr(i, 2), 16) <<
                                  (24 - (i % 8) * 4);
                              return new c.init(r, t / 2);
                            },
                          }),
                          f = (u.Latin1 = {
                            stringify: function (e) {
                              for (
                                var t = e.words, r = e.sigBytes, i = [], n = 0;
                                n < r;
                                n++
                              ) {
                                var o =
                                  (t[n >>> 2] >>> (24 - (n % 4) * 8)) & 255;
                                i.push(String.fromCharCode(o));
                              }
                              return i.join("");
                            },
                            parse: function (e) {
                              for (var t = e.length, r = [], i = 0; i < t; i++)
                                r[i >>> 2] |=
                                  (255 & e.charCodeAt(i)) << (24 - (i % 4) * 8);
                              return new c.init(r, t);
                            },
                          }),
                          h = (u.Utf8 = {
                            stringify: function (e) {
                              try {
                                return decodeURIComponent(
                                  escape(f.stringify(e))
                                );
                              } catch (e) {
                                throw Error("Malformed UTF-8 data");
                              }
                            },
                            parse: function (e) {
                              return f.parse(unescape(encodeURIComponent(e)));
                            },
                          }),
                          d = (s.BufferedBlockAlgorithm = a.extend({
                            reset: function () {
                              (this._data = new c.init()),
                                (this._nDataBytes = 0);
                            },
                            _append: function (e) {
                              "string" == typeof e && (e = h.parse(e)),
                                this._data.concat(e),
                                (this._nDataBytes += e.sigBytes);
                            },
                            _process: function (t) {
                              var r,
                                i = this._data,
                                n = i.words,
                                o = i.sigBytes,
                                s = this.blockSize,
                                a = o / (4 * s),
                                u =
                                  (t
                                    ? e.ceil(a)
                                    : e.max((0 | a) - this._minBufferSize, 0)) *
                                  s,
                                t = e.min(4 * u, o);
                              if (u) {
                                for (var l = 0; l < u; l += s)
                                  this._doProcessBlock(n, l);
                                (r = n.splice(0, u)), (i.sigBytes -= t);
                              }
                              return new c.init(r, t);
                            },
                            clone: function () {
                              var e = a.clone.call(this);
                              return (e._data = this._data.clone()), e;
                            },
                            _minBufferSize: 0,
                          })),
                          p =
                            ((s.Hasher = d.extend({
                              cfg: a.extend(),
                              init: function (e) {
                                (this.cfg = this.cfg.extend(e)), this.reset();
                              },
                              reset: function () {
                                d.reset.call(this), this._doReset();
                              },
                              update: function (e) {
                                return this._append(e), this._process(), this;
                              },
                              finalize: function (e) {
                                return e && this._append(e), this._doFinalize();
                              },
                              blockSize: 16,
                              _createHelper: function (e) {
                                return function (t, r) {
                                  return new e.init(r).finalize(t);
                                };
                              },
                              _createHmacHelper: function (e) {
                                return function (t, r) {
                                  return new p.HMAC.init(e, r).finalize(t);
                                };
                              },
                            })),
                            (o.algo = {}));
                        return o;
                      })(Math);
                    }),
                    c = n(function (e, t) {
                      var r, i, n, o, s, c, u;
                      e.exports =
                        ((r = Math),
                        (i = (u = a.lib).WordArray),
                        (n = u.Hasher),
                        (u = a.algo),
                        (o = []),
                        (s = []),
                        (() => {
                          function e(e) {
                            return (0x100000000 * (e - (0 | e))) | 0;
                          }
                          for (var t = 2, i = 0; i < 64; )
                            !(function (e) {
                              for (var t = r.sqrt(e), i = 2; i <= t; i++)
                                if (!(e % i)) return;
                              return 1;
                            })(t) ||
                              (i < 8 && (o[i] = e(r.pow(t, 0.5))),
                              (s[i] = e(r.pow(t, 1 / 3))),
                              i++),
                              t++;
                        })(),
                        (c = []),
                        (u = u.SHA256 =
                          n.extend({
                            _doReset: function () {
                              this._hash = new i.init(o.slice(0));
                            },
                            _doProcessBlock: function (e, t) {
                              for (
                                var r = this._hash.words,
                                  i = r[0],
                                  n = r[1],
                                  o = r[2],
                                  a = r[3],
                                  u = r[4],
                                  l = r[5],
                                  f = r[6],
                                  h = r[7],
                                  d = 0;
                                d < 64;
                                d++
                              ) {
                                c[d] =
                                  d < 16
                                    ? 0 | e[t + d]
                                    : ((((p = c[d - 15]) << 25) | (p >>> 7)) ^
                                        ((p << 14) | (p >>> 18)) ^
                                        (p >>> 3)) +
                                      c[d - 7] +
                                      ((((p = c[d - 2]) << 15) | (p >>> 17)) ^
                                        ((p << 13) | (p >>> 19)) ^
                                        (p >>> 10)) +
                                      c[d - 16];
                                var p = (i & n) ^ (i & o) ^ (n & o),
                                  g =
                                    h +
                                    (((u << 26) | (u >>> 6)) ^
                                      ((u << 21) | (u >>> 11)) ^
                                      ((u << 7) | (u >>> 25))) +
                                    ((u & l) ^ (~u & f)) +
                                    s[d] +
                                    c[d],
                                  h = f,
                                  f = l,
                                  l = u,
                                  u = (a + g) | 0,
                                  a = o,
                                  o = n,
                                  n = i,
                                  i =
                                    (g +
                                      ((((i << 30) | (i >>> 2)) ^
                                        ((i << 19) | (i >>> 13)) ^
                                        ((i << 10) | (i >>> 22))) +
                                        p)) |
                                    0;
                              }
                              (r[0] = (r[0] + i) | 0),
                                (r[1] = (r[1] + n) | 0),
                                (r[2] = (r[2] + o) | 0),
                                (r[3] = (r[3] + a) | 0),
                                (r[4] = (r[4] + u) | 0),
                                (r[5] = (r[5] + l) | 0),
                                (r[6] = (r[6] + f) | 0),
                                (r[7] = (r[7] + h) | 0);
                            },
                            _doFinalize: function () {
                              var e = this._data,
                                t = e.words,
                                i = 8 * this._nDataBytes,
                                n = 8 * e.sigBytes;
                              return (
                                (t[n >>> 5] |= 128 << (24 - (n % 32))),
                                (t[14 + (((64 + n) >>> 9) << 4)] = r.floor(
                                  i / 0x100000000
                                )),
                                (t[15 + (((64 + n) >>> 9) << 4)] = i),
                                (e.sigBytes = 4 * t.length),
                                this._process(),
                                this._hash
                              );
                            },
                            clone: function () {
                              var e = n.clone.call(this);
                              return (e._hash = this._hash.clone()), e;
                            },
                          })),
                        (a.SHA256 = n._createHelper(u)),
                        (a.HmacSHA256 = n._createHmacHelper(u)),
                        a.SHA256);
                    }),
                    u =
                      (n(function (e, t) {
                        var r;
                        e.exports =
                          ((e = a.lib.Base),
                          (r = a.enc.Utf8),
                          void (a.algo.HMAC = e.extend({
                            init: function (e, t) {
                              (e = this._hasher = new e.init()),
                                "string" == typeof t && (t = r.parse(t));
                              var i = e.blockSize,
                                n = 4 * i;
                              (t = t.sigBytes > n ? e.finalize(t) : t).clamp();
                              for (
                                var e = (this._oKey = t.clone()),
                                  t = (this._iKey = t.clone()),
                                  o = e.words,
                                  s = t.words,
                                  a = 0;
                                a < i;
                                a++
                              )
                                (o[a] ^= 0x5c5c5c5c), (s[a] ^= 0x36363636);
                              (e.sigBytes = t.sigBytes = n), this.reset();
                            },
                            reset: function () {
                              var e = this._hasher;
                              e.reset(), e.update(this._iKey);
                            },
                            update: function (e) {
                              return this._hasher.update(e), this;
                            },
                            finalize: function (e) {
                              var t = this._hasher,
                                e = t.finalize(e);
                              return (
                                t.reset(),
                                t.finalize(this._oKey.clone().concat(e))
                              );
                            },
                          })));
                      }),
                      n(function (e, t) {
                        e.exports = a.HmacSHA256;
                      })),
                    l = function (e, t) {
                      return u(t, e);
                    },
                    f = function (e) {
                      return c(e);
                    },
                    h = [
                      "authorization",
                      "content-type",
                      "content-length",
                      "user-agent",
                      "presigned-expires",
                      "expect",
                      "x-amzn-trace-id",
                    ];
                  return (() => {
                    function e(t, r, i) {
                      ((t) => {
                        if (!(t instanceof e))
                          throw TypeError("Cannot call a class as a function");
                      })(this),
                        (this.request = t),
                        (this.request.headers = t.headers || {}),
                        (this.serviceName = r),
                        (this.signatureCache =
                          "boolean" != typeof (i = i || {}).signatureCache ||
                          i.signatureCache),
                        (this.operation = i.operation),
                        (this.signatureVersion = i.signatureVersion),
                        (this.constant = i.isVolcengine
                          ? {
                              algorithm: "HMAC-SHA256",
                              v4Identifier: "request",
                              dateHeader: "X-Date",
                              tokenHeader: "x-security-token",
                              contentSha256Header: "X-Content-Sha256",
                              kDatePrefix: "",
                            }
                          : {
                              algorithm: "AWS4-HMAC-SHA256",
                              v4Identifier: "aws4_request",
                              dateHeader: "X-Amz-Date",
                              tokenHeader: "x-amz-security-token",
                              contentSha256Header: "X-Amz-Content-Sha256",
                              kDatePrefix: "AWS4",
                            }),
                        (this.bodySha256 = i.bodySha256),
                        (this.shouldSerializeBody =
                          "boolean" != typeof i.shouldSerializeBody ||
                          i.shouldSerializeBody);
                    }
                    return (
                      (function (e, t) {
                        for (var r, i = 0; i < t.length; i++) {
                          var n = t[i];
                          (n.enumerable = n.enumerable || !1),
                            (n.configurable = !0),
                            "value" in n && (n.writable = !0),
                            Object.defineProperty(
                              e,
                              "symbol" ==
                                typeof (r = ((e) => {
                                  if ("object" != typeof e || null === e)
                                    return e;
                                  var t = e[Symbol.toPrimitive];
                                  if (void 0 === t) return String(e);
                                  if (
                                    "object" != typeof (t = t.call(e, "string"))
                                  )
                                    return t;
                                  throw TypeError(
                                    "@@toPrimitive must return a primitive value."
                                  );
                                })(n.key))
                                ? r
                                : String(r),
                              n
                            );
                        }
                      })(e.prototype, [
                        {
                          key: "addAuthorization",
                          value: function (e, t) {
                            (t = this.iso8601(t).replace(/[:\-]|\.\d{3}/g, "")),
                              this.addHeaders(e, t),
                              (this.request.headers.Authorization =
                                this.authorization(e, t));
                          },
                        },
                        {
                          key: "addHeaders",
                          value: function (e, t) {
                            (this.request.headers[this.constant.dateHeader] =
                              t),
                              e.sessionToken &&
                                (this.request.headers[
                                  this.constant.tokenHeader
                                ] = e.sessionToken),
                              this.request.body &&
                                ("string" != typeof (t = this.request.body) &&
                                  this.shouldSerializeBody &&
                                  (t =
                                    t instanceof URLSearchParams
                                      ? t.toString()
                                      : JSON.stringify(t)),
                                (this.request.headers[
                                  this.constant.contentSha256Header
                                ] = this.bodySha256 || f(t).toString()));
                          },
                        },
                        {
                          key: "authorization",
                          value: function (e, t) {
                            var r = [],
                              i = this.credentialString(t);
                            return (
                              r.push(
                                ""
                                  .concat(
                                    this.constant.algorithm,
                                    " Credential="
                                  )
                                  .concat(e.accessKeyId, "/")
                                  .concat(i)
                              ),
                              r.push(
                                "SignedHeaders=".concat(this.signedHeaders())
                              ),
                              r.push("Signature=".concat(this.signature(e, t))),
                              r.join(", ")
                            );
                          },
                        },
                        {
                          key: "signature",
                          value: function (e, t) {
                            return l(
                              (e = this.getSigningKey(
                                e,
                                t.substr(0, 8),
                                this.request.region,
                                this.serviceName,
                                this.signatureCache
                              )),
                              this.stringToSign(t),
                              "hex"
                            );
                          },
                        },
                        {
                          key: "stringToSign",
                          value: function (e) {
                            var t = [];
                            return (
                              t.push(this.constant.algorithm),
                              t.push(e),
                              t.push(this.credentialString(e)),
                              t.push(
                                this.hexEncodedHash(this.canonicalString())
                              ),
                              t.join("\n")
                            );
                          },
                        },
                        {
                          key: "canonicalString",
                          value: function () {
                            var e = [],
                              t = this.request.pathname || "/";
                            return (
                              e.push(this.request.method.toUpperCase()),
                              e.push(t),
                              e.push(s(this.request.params) || ""),
                              e.push("".concat(this.canonicalHeaders(), "\n")),
                              e.push(this.signedHeaders()),
                              e.push(this.hexEncodedBodyHash()),
                              e.join("\n")
                            );
                          },
                        },
                        {
                          key: "canonicalHeaders",
                          value: function () {
                            var e = this,
                              t = [],
                              r =
                                (Object.keys(this.request.headers).forEach(
                                  function (r) {
                                    t.push([r, e.request.headers[r]]);
                                  }
                                ),
                                t.sort(function (e, t) {
                                  return e[0].toLowerCase() < t[0].toLowerCase()
                                    ? -1
                                    : 1;
                                }),
                                []);
                            return (
                              t.forEach(function (t) {
                                var i = t[0].toLowerCase();
                                if (e.isSignableHeader(i)) {
                                  if (
                                    null == (t = t[1]) ||
                                    "function" != typeof t.toString
                                  )
                                    throw Error(
                                      "Header ".concat(
                                        i,
                                        " contains invalid value"
                                      )
                                    );
                                  r.push(
                                    ""
                                      .concat(i, ":")
                                      .concat(
                                        e.canonicalHeaderValues(t.toString())
                                      )
                                  );
                                }
                              }),
                              r.join("\n")
                            );
                          },
                        },
                        {
                          key: "canonicalHeaderValues",
                          value: function (e) {
                            return e
                              .replace(/\s+/g, " ")
                              .replace(/^\s+|\s+$/g, "");
                          },
                        },
                        {
                          key: "signedHeaders",
                          value: function () {
                            var e = this,
                              t = [];
                            return (
                              Object.keys(this.request.headers).forEach(
                                function (r) {
                                  (r = r.toLowerCase()),
                                    e.isSignableHeader(r) && t.push(r);
                                }
                              ),
                              t.sort().join(";")
                            );
                          },
                        },
                        {
                          key: "credentialString",
                          value: function (e) {
                            return this.createScope(
                              e.substr(0, 8),
                              this.request.region,
                              this.serviceName
                            );
                          },
                        },
                        {
                          key: "hexEncodedHash",
                          value: function (e) {
                            return f(e);
                          },
                        },
                        {
                          key: "hexEncodedBodyHash",
                          value: function () {
                            return (
                              this.request.headers[
                                this.constant.contentSha256Header
                              ] ||
                              (this.request.body
                                ? this.hexEncodedHash(s(this.request.body))
                                : this.hexEncodedHash(""))
                            );
                          },
                        },
                        {
                          key: "isSignableHeader",
                          value: function (e) {
                            return (
                              0 === e.toLowerCase().indexOf("x-amz-") ||
                              0 > h.indexOf(e)
                            );
                          },
                        },
                        {
                          key: "iso8601",
                          value: function (e) {
                            return (e = void 0 === e ? new Date() : e)
                              .toISOString()
                              .replace(/\.\d{3}Z$/, "Z");
                          },
                        },
                        {
                          key: "getSigningKey",
                          value: function (e, t, r, i) {
                            return (
                              (e = l(
                                ""
                                  .concat(this.constant.kDatePrefix)
                                  .concat(e.secretAccessKey),
                                t
                              )),
                              (t = l(e, r)),
                              (e = l(t, i)),
                              l(e, this.constant.v4Identifier)
                            );
                          },
                        },
                        {
                          key: "createScope",
                          value: function (e, t, r) {
                            return [
                              e.substr(0, 8),
                              t,
                              r,
                              this.constant.v4Identifier,
                            ].join("/");
                          },
                        },
                      ]),
                      Object.defineProperty(e, "prototype", { writable: !1 }),
                      e
                    );
                  })();
                })(r(9));
              }).call(this, r(5));
            },
            function (e, t, r) {
              e.exports = function () {
                return r(10)(
                  '(r=>{var n={};function __webpack_require__(e){var t;return(n[e]||(t=n[e]={i:e,l:!1,exports:{}},r[e].call(t.exports,t,t.exports,__webpack_require__),t.l=!0,t)).exports}__webpack_require__.m=r,__webpack_require__.c=n,__webpack_require__.d=function(e,t,r){__webpack_require__.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:r})},__webpack_require__.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},__webpack_require__.t=function(t,e){if(1&e&&(t=__webpack_require__(t)),8&e)return t;if(4&e&&"object"==typeof t&&t&&t.__esModule)return t;var r=Object.create(null);if(__webpack_require__.r(r),Object.defineProperty(r,"default",{enumerable:!0,value:t}),2&e&&"string"!=typeof t)for(var n in t)__webpack_require__.d(r,n,function(e){return t[e]}.bind(null,n));return r},__webpack_require__.n=function(e){var t=e&&e.__esModule?function getDefault(){return e.default}:function getModuleExports(){return e};return __webpack_require__.d(t,"a",t),t},__webpack_require__.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},__webpack_require__.p="",__webpack_require__(__webpack_require__.s=9)})([function(e,t,l){!function(d){e.exports=(()=>(f=>{var n;if("undefined"!=typeof window&&window.crypto&&(n=window.crypto),"undefined"!=typeof self&&self.crypto&&(n=self.crypto),!(n=!(n=!(n="undefined"!=typeof globalThis&&globalThis.crypto?globalThis.crypto:n)&&"undefined"!=typeof window&&window.msCrypto?window.msCrypto:n)&&void 0!==d&&d.crypto?d.crypto:n))try{n=l(11)}catch(e){}var r=Object.create||(()=>{function F(){}return function(e){return F.prototype=e,e=new F,F.prototype=null,e}})(),e={},t=e.lib={},i=t.Base={extend:function(e){var t=r(this);return e&&t.mixIn(e),t.hasOwnProperty("init")&&this.init!==t.init||(t.init=function(){t.$super.init.apply(this,arguments)}),(t.init.prototype=t).$super=this,t},create:function(){var e=this.extend();return e.init.apply(e,arguments),e},init:function(){},mixIn:function(e){for(var t in e)e.hasOwnProperty(t)&&(this[t]=e[t]);e.hasOwnProperty("toString")&&(this.toString=e.toString)},clone:function(){return this.init.prototype.extend(this)}},u=t.WordArray=i.extend({init:function(e,t){e=this.words=e||[],this.sigBytes=null!=t?t:4*e.length},toString:function(e){return(e||s).stringify(this)},concat:function(e){var t=this.words,r=e.words,n=this.sigBytes,i=e.sigBytes;if(this.clamp(),n%4)for(var o=0;o<i;o++){var s=r[o>>>2]>>>24-o%4*8&255;t[n+o>>>2]|=s<<24-(n+o)%4*8}else for(var c=0;c<i;c+=4)t[n+c>>>2]=r[c>>>2];return this.sigBytes+=i,this},clamp:function(){var e=this.words,t=this.sigBytes;e[t>>>2]&=4294967295<<32-t%4*8,e.length=f.ceil(t/4)},clone:function(){var e=i.clone.call(this);return e.words=this.words.slice(0),e},random:function(e){for(var t=[],r=0;r<e;r+=4)t.push((()=>{if(n){if("function"==typeof n.getRandomValues)try{return n.getRandomValues(new Uint32Array(1))[0]}catch(e){}if("function"==typeof n.randomBytes)try{return n.randomBytes(4).readInt32LE()}catch(e){}}throw new Error("Native crypto module could not be used to get secure random number.")})());return new u.init(t,e)}}),o=e.enc={},s=o.Hex={stringify:function(e){for(var t=e.words,r=e.sigBytes,n=[],i=0;i<r;i++){var o=t[i>>>2]>>>24-i%4*8&255;n.push((o>>>4).toString(16)),n.push((15&o).toString(16))}return n.join("")},parse:function(e){for(var t=e.length,r=[],n=0;n<t;n+=2)r[n>>>3]|=parseInt(e.substr(n,2),16)<<24-n%8*4;return new u.init(r,t/2)}},c=o.Latin1={stringify:function(e){for(var t=e.words,r=e.sigBytes,n=[],i=0;i<r;i++){var o=t[i>>>2]>>>24-i%4*8&255;n.push(String.fromCharCode(o))}return n.join("")},parse:function(e){for(var t=e.length,r=[],n=0;n<t;n++)r[n>>>2]|=(255&e.charCodeAt(n))<<24-n%4*8;return new u.init(r,t)}},a=o.Utf8={stringify:function(e){try{return decodeURIComponent(escape(c.stringify(e)))}catch(e){throw new Error("Malformed UTF-8 data")}},parse:function(e){return c.parse(unescape(encodeURIComponent(e)))}},h=t.BufferedBlockAlgorithm=i.extend({reset:function(){this._data=new u.init,this._nDataBytes=0},_append:function(e){"string"==typeof e&&(e=a.parse(e)),this._data.concat(e),this._nDataBytes+=e.sigBytes},_process:function(e){var t,r=this._data,n=r.words,i=r.sigBytes,o=this.blockSize,s=i/(4*o),c=(s=e?f.ceil(s):f.max((0|s)-this._minBufferSize,0))*o,e=f.min(4*c,i);if(c){for(var a=0;a<c;a+=o)this._doProcessBlock(n,a);t=n.splice(0,c),r.sigBytes-=e}return new u.init(t,e)},clone:function(){var e=i.clone.call(this);return e._data=this._data.clone(),e},_minBufferSize:0}),p=(t.Hasher=h.extend({cfg:i.extend(),init:function(e){this.cfg=this.cfg.extend(e),this.reset()},reset:function(){h.reset.call(this),this._doReset()},update:function(e){return this._append(e),this._process(),this},finalize:function(e){return e&&this._append(e),this._doFinalize()},blockSize:16,_createHelper:function(r){return function(e,t){return new r.init(t).finalize(e)}},_createHmacHelper:function(r){return function(e,t){return new p.HMAC.init(r,t).finalize(e)}}}),e.algo={});return e})(Math))()}.call(this,l(10))},function(e,t,r){e.exports=(l=>{l.lib.Cipher||(()=>{var e=l,t=e.lib,r=t.Base,s=t.WordArray,n=t.BufferedBlockAlgorithm,i=((a=e.enc).Utf8,a.Base64),o=e.algo.EvpKDF,c=t.Cipher=n.extend({cfg:r.extend(),createEncryptor:function(e,t){return this.create(this._ENC_XFORM_MODE,e,t)},createDecryptor:function(e,t){return this.create(this._DEC_XFORM_MODE,e,t)},init:function(e,t,r){this.cfg=this.cfg.extend(r),this._xformMode=e,this._key=t,this.reset()},reset:function(){n.reset.call(this),this._doReset()},process:function(e){return this._append(e),this._process()},finalize:function(e){return e&&this._append(e),this._doFinalize()},keySize:4,ivSize:4,_ENC_XFORM_MODE:1,_DEC_XFORM_MODE:2,_createHelper:(()=>{function selectCipherStrategy(e){return"string"==typeof e?d:p}return function(n){return{encrypt:function(e,t,r){return selectCipherStrategy(t).encrypt(n,e,t,r)},decrypt:function(e,t,r){return selectCipherStrategy(t).decrypt(n,e,t,r)}}}})()}),a=(t.StreamCipher=c.extend({_doFinalize:function(){return this._process(!0)},blockSize:1}),e.mode={}),f=t.BlockCipherMode=r.extend({createEncryptor:function(e,t){return this.Encryptor.create(e,t)},createDecryptor:function(e,t){return this.Decryptor.create(e,t)},init:function(e,t){this._cipher=e,this._iv=t}}),a=a.CBC=(()=>{var e=f.extend();function xorBlock(e,t,r){var n,i=this._iv;i?(n=i,this._iv=void 0):n=this._prevBlock;for(var o=0;o<r;o++)e[t+o]^=n[o]}return e.Encryptor=e.extend({processBlock:function(e,t){var r=this._cipher,n=r.blockSize;xorBlock.call(this,e,t,n),r.encryptBlock(e,t),this._prevBlock=e.slice(t,t+n)}}),e.Decryptor=e.extend({processBlock:function(e,t){var r=this._cipher,n=r.blockSize,i=e.slice(t,t+n);r.decryptBlock(e,t),xorBlock.call(this,e,t,n),this._prevBlock=i}}),e})(),u=(e.pad={}).Pkcs7={pad:function(e,t){for(var t=4*t,r=t-e.sigBytes%t,n=r<<24|r<<16|r<<8|r,i=[],o=0;o<r;o+=4)i.push(n);t=s.create(i,r);e.concat(t)},unpad:function(e){var t=255&e.words[e.sigBytes-1>>>2];e.sigBytes-=t}},h=(t.BlockCipher=c.extend({cfg:c.cfg.extend({mode:a,padding:u}),reset:function(){c.reset.call(this);var e,t=this.cfg,r=t.iv,t=t.mode;this._xformMode==this._ENC_XFORM_MODE?e=t.createEncryptor:(e=t.createDecryptor,this._minBufferSize=1),this._mode&&this._mode.__creator==e?this._mode.init(this,r&&r.words):(this._mode=e.call(t,this,r&&r.words),this._mode.__creator=e)},_doProcessBlock:function(e,t){this._mode.processBlock(e,t)},_doFinalize:function(){var e,t=this.cfg.padding;return this._xformMode==this._ENC_XFORM_MODE?(t.pad(this._data,this.blockSize),e=this._process(!0)):(e=this._process(!0),t.unpad(e)),e},blockSize:4}),t.CipherParams=r.extend({init:function(e){this.mixIn(e)},toString:function(e){return(e||this.formatter).stringify(this)}})),a=(e.format={}).OpenSSL={stringify:function(e){var t=e.ciphertext,e=e.salt,e=e?s.create([1398893684,1701076831]).concat(e).concat(t):t;return e.toString(i)},parse:function(e){var t,e=i.parse(e),r=e.words;return 1398893684==r[0]&&1701076831==r[1]&&(t=s.create(r.slice(2,4)),r.splice(0,4),e.sigBytes-=16),h.create({ciphertext:e,salt:t})}},p=t.SerializableCipher=r.extend({cfg:r.extend({format:a}),encrypt:function(e,t,r,n){n=this.cfg.extend(n);var i=e.createEncryptor(r,n),t=i.finalize(t),i=i.cfg;return h.create({ciphertext:t,key:r,iv:i.iv,algorithm:e,mode:i.mode,padding:i.padding,blockSize:e.blockSize,formatter:n.format})},decrypt:function(e,t,r,n){return n=this.cfg.extend(n),t=this._parse(t,n.format),e.createDecryptor(r,n).finalize(t.ciphertext)},_parse:function(e,t){return"string"==typeof e?t.parse(e,this):e}}),u=(e.kdf={}).OpenSSL={execute:function(e,t,r,n,i){n=n||s.random(8),i=(i?o.create({keySize:t+r,hasher:i}):o.create({keySize:t+r})).compute(e,n);e=s.create(i.words.slice(t),4*r);return i.sigBytes=4*t,h.create({key:i,iv:e,salt:n})}},d=t.PasswordBasedCipher=p.extend({cfg:p.cfg.extend({kdf:u}),encrypt:function(e,t,r,n){r=(n=this.cfg.extend(n)).kdf.execute(r,e.keySize,e.ivSize,n.salt,n.hasher),n.iv=r.iv,e=p.encrypt.call(this,e,t,r.key,n);return e.mixIn(r),e},decrypt:function(e,t,r,n){n=this.cfg.extend(n),t=this._parse(t,n.format);r=n.kdf.execute(r,e.keySize,e.ivSize,t.salt,n.hasher);return n.iv=r.iv,p.decrypt.call(this,e,t,r.key,n)}})})()})(r(0),r(5))},function(e,t,r){e.exports=(n=>((()=>{var e=n,t=e.lib.BlockCipher,r=e.algo,f=[],u=[],h=[],p=[],d=[],l=[],_=[],y=[],g=[],v=[],w=((()=>{for(var e=[],t=0;t<256;t++)e[t]=t<128?t<<1:t<<1^283;for(var r=0,n=0,t=0;t<256;t++){var i=n^n<<1^n<<2^n<<3^n<<4,o=e[u[f[r]=i=i>>>8^255&i^99]=r],s=e[o],c=e[s],a=257*e[i]^16843008*i;h[r]=a<<24|a>>>8,p[r]=a<<16|a>>>16,d[r]=a<<8|a>>>24,l[r]=a,_[i]=(a=16843009*c^65537*s^257*o^16843008*r)<<24|a>>>8,y[i]=a<<16|a>>>16,g[i]=a<<8|a>>>24,v[i]=a,r?(r=o^e[e[e[c^o]]],n^=e[e[n]]):r=n=1}})(),[0,1,2,4,8,16,32,64,128,27,54]),r=r.AES=t.extend({_doReset:function(){if(!this._nRounds||this._keyPriorReset!==this._key){for(var e=this._keyPriorReset=this._key,t=e.words,r=e.sigBytes/4,n=4*(1+(this._nRounds=6+r)),i=this._keySchedule=[],o=0;o<n;o++)o<r?i[o]=t[o]:(a=i[o-1],o%r?6<r&&o%r==4&&(a=f[a>>>24]<<24|f[a>>>16&255]<<16|f[a>>>8&255]<<8|f[255&a]):(a=f[(a=a<<8|a>>>24)>>>24]<<24|f[a>>>16&255]<<16|f[a>>>8&255]<<8|f[255&a],a^=w[o/r|0]<<24),i[o]=i[o-r]^a);for(var s=this._invKeySchedule=[],c=0;c<n;c++){var a,o=n-c;a=c%4?i[o]:i[o-4],s[c]=c<4||o<=4?a:_[f[a>>>24]]^y[f[a>>>16&255]]^g[f[a>>>8&255]]^v[f[255&a]]}}},encryptBlock:function(e,t){this._doCryptBlock(e,t,this._keySchedule,h,p,d,l,f)},decryptBlock:function(e,t){var r=e[t+1],r=(e[t+1]=e[t+3],e[t+3]=r,this._doCryptBlock(e,t,this._invKeySchedule,_,y,g,v,u),e[t+1]);e[t+1]=e[t+3],e[t+3]=r},_doCryptBlock:function(e,t,r,n,i,o,s,c){for(var a=this._nRounds,f=e[t]^r[0],u=e[t+1]^r[1],h=e[t+2]^r[2],p=e[t+3]^r[3],d=4,l=1;l<a;l++)var _=n[f>>>24]^i[u>>>16&255]^o[h>>>8&255]^s[255&p]^r[d++],y=n[u>>>24]^i[h>>>16&255]^o[p>>>8&255]^s[255&f]^r[d++],g=n[h>>>24]^i[p>>>16&255]^o[f>>>8&255]^s[255&u]^r[d++],v=n[p>>>24]^i[f>>>16&255]^o[u>>>8&255]^s[255&h]^r[d++],f=_,u=y,h=g,p=v;_=(c[f>>>24]<<24|c[u>>>16&255]<<16|c[h>>>8&255]<<8|c[255&p])^r[d++],y=(c[u>>>24]<<24|c[h>>>16&255]<<16|c[p>>>8&255]<<8|c[255&f])^r[d++],g=(c[h>>>24]<<24|c[p>>>16&255]<<16|c[f>>>8&255]<<8|c[255&u])^r[d++],v=(c[p>>>24]<<24|c[f>>>16&255]<<16|c[u>>>8&255]<<8|c[255&h])^r[d++];e[t]=_,e[t+1]=y,e[t+2]=g,e[t+3]=v},keySize:8});e.AES=t._createHelper(r)})(),n.AES))(r(0),(r(12),r(13),r(5),r(1)))},function(e,t,r){e.exports=(t=>(t.mode.ECB=(()=>{var e=t.lib.BlockCipherMode.extend();return e.Encryptor=e.extend({processBlock:function(e,t){this._cipher.encryptBlock(e,t)}}),e.Decryptor=e.extend({processBlock:function(e,t){this._cipher.decryptBlock(e,t)}}),e})(),t.mode.ECB))(r(0),r(1))},function(e,t,r){e.exports=(e=>e.enc.Utf8)(r(0))},function(e,t,r){e.exports=(o=>((()=>{var e=o,t=e.lib,r=t.Base,u=t.WordArray,n=(t=e.algo).MD5,i=t.EvpKDF=r.extend({cfg:r.extend({keySize:4,hasher:n,iterations:1}),init:function(e){this.cfg=this.cfg.extend(e)},compute:function(e,t){for(var r,n=this.cfg,i=n.hasher.create(),o=u.create(),s=o.words,c=n.keySize,a=n.iterations;s.length<c;){r&&i.update(r),r=i.update(e).finalize(t),i.reset();for(var f=1;f<a;f++)r=i.finalize(r),i.reset();o.concat(r)}return o.sigBytes=4*c,o}});e.EvpKDF=function(e,t,r){return i.create(r).compute(e,t)}})(),o.EvpKDF))(r(0),(r(14),r(15)))},function(e,t,r){e.exports=(e=>e.pad.Pkcs7)(r(0),r(1))},function(e,t,r){e.exports=(e=>(e.pad.NoPadding={pad:function(){},unpad:function(){}},e.pad.NoPadding))(r(0),r(1))},function(e,t,r){e.exports=(t=>((()=>{var e,i;"function"==typeof ArrayBuffer&&(e=t.lib.WordArray,i=e.init,(e.init=function(e){if((e=(e=e instanceof ArrayBuffer?new Uint8Array(e):e)instanceof Int8Array||"undefined"!=typeof Uint8ClampedArray&&e instanceof Uint8ClampedArray||e instanceof Int16Array||e instanceof Uint16Array||e instanceof Int32Array||e instanceof Uint32Array||e instanceof Float32Array||e instanceof Float64Array?new Uint8Array(e.buffer,e.byteOffset,e.byteLength):e)instanceof Uint8Array){for(var t=e.byteLength,r=[],n=0;n<t;n++)r[n>>>2]|=e[n]<<24-n%4*8;i.call(this,r,t)}else i.apply(this,arguments)}).prototype=e)})(),t.lib.WordArray))(r(0))},function(e,t,r){r.r(t);var t=r(2),s=r.n(t),t=r(3),c=r.n(t),t=r(6),a=r.n(t),t=r(7),f=r.n(t),t=r(8),u=r.n(t),t=r(4),h=r.n(t);function crc32(e,t){for(var r=[0,1996959894,3993919788,2567524794,124634137,1886057615,3915621685,2657392035,249268274,2044508324,3772115230,2547177864,162941995,2125561021,3887607047,2428444049,498536548,1789927666,4089016648,2227061214,450548861,1843258603,4107580753,2211677639,325883990,1684777152,4251122042,2321926636,335633487,1661365465,4195302755,2366115317,997073096,1281953886,3579855332,2724688242,1006888145,1258607687,3524101629,2768942443,901097722,1119000684,3686517206,2898065728,853044451,1172266101,3705015759,2882616665,651767980,1373503546,3369554304,3218104598,565507253,1454621731,3485111705,3099436303,671266974,1594198024,3322730930,2970347812,795835527,1483230225,3244367275,3060149565,1994146192,31158534,2563907772,4023717930,1907459465,112637215,2680153253,3904427059,2013776290,251722036,2517215374,3775830040,2137656763,141376813,2439277719,3865271297,1802195444,476864866,2238001368,4066508878,1812370925,453092731,2181625025,4111451223,1706088902,314042704,2344532202,4240017532,1658658271,366619977,2362670323,4224994405,1303535960,984961486,2747007092,3569037538,1256170817,1037604311,2765210733,3554079995,1131014506,879679996,2909243462,3663771856,1141124467,855842277,2852801631,3708648649,1342533948,654459306,3188396048,3373015174,1466479909,544179635,3110523913,3462522015,1591671054,702138776,2966460450,3352799412,1504918807,783551873,3082640443,3233442989,3988292384,2596254646,62317068,1957810842,3939845945,2647816111,81470997,1943803523,3814918930,2489596804,225274430,2053790376,3826175755,2466906013,167816743,2097651377,4027552580,2265490386,503444072,1762050814,4150417245,2154129355,426522225,1852507879,4275313526,2312317920,282753626,1742555852,4189708143,2394877945,397917763,1622183637,3604390888,2714866558,953729732,1340076626,3518719985,2797360999,1068828381,1219638859,3624741850,2936675148,906185462,1090812512,3747672003,2825379669,829329135,1181335161,3412177804,3160834842,628085408,1382605366,3423369109,3138078467,570562233,1426400815,3317316542,2998733608,733239954,1555261956,3268935591,3050360625,752459403,1541320221,2607071920,3965973030,1969922972,40735498,2617837225,3943577151,1913087877,83908371,2512341634,3803740692,2075208622,213261112,2463272603,3855990285,2094854071,198958881,2262029012,4057260610,1759359992,534414190,2176718541,4139329115,1873836001,414664567,2282248934,4279200368,1711684554,285281116,2405801727,4167216745,1634467795,376229701,2685067896,3608007406,1308918612,956543938,2808555105,3495958263,1231636301,1047427035,2932959818,3654703836,1088359270,936918e3,2847714899,3736837829,1202900863,817233897,3183342108,3401237130,1404277552,615818150,3134207493,3453421203,1423857449,601450431,3009837614,3294710456,1567103746,711928724,3020668471,3272380065,1510334235,755167117],n=("undefined"!=typeof Int32Array&&(r=new Int32Array(r)),-1^~~t),i=(e=new Uint8Array(e)).length,o=0;o<i;o++)n=r[255&(n^e[o])]^n>>>8;return(-1^n)>>>0}function dec2hex(e){if(void 0!==e)return function toEight(e){return e.length<8?toEight(e="0".concat(e)):e}(Number(e).toString(16))}self.onmessage=function(e){var e=e.data,t=e[0],r=e[1],n=e[2],i=e[4],o=e[5];e[3]?(e=u.a.create(t),e=crc32(o=function wordArrayToUint8Array(e){for(var t=e.sigBytes,r=e.words,n=new Uint8Array(t),i=0,o=0;i!==t;){var s=r[o++];if(n[i++]=(4278190080&s)>>>24,i===t)break;if(n[i++]=(16711680&s)>>>16,i===t)break;if(n[i++]=(65280&s)>>>8,i===t)break;n[i++]=255&s}return n}((o&&t.byteLength%16!=0?s.a.encrypt(e,h.a.parse(i),{mode:c.a,padding:a.a}):s.a.encrypt(e,h.a.parse(i),{mode:c.a,padding:f.a})).ciphertext),0),postMessage([o.buffer,dec2hex(e),r,n],[o.buffer])):(i=crc32(t,0),postMessage([t,dec2hex(i),r,n],[t]))}},function(e,t){var r=function(){return this}();try{r=r||new Function("return this")()}catch(e){"object"==typeof window&&(r=window)}e.exports=r},function(e,t){},function(e,t,r){e.exports=(e=>((()=>{var a=e.lib.WordArray;e.enc.Base64={stringify:function(e){for(var t=e.words,r=e.sigBytes,n=this._map,i=(e.clamp(),[]),o=0;o<r;o+=3)for(var s=(t[o>>>2]>>>24-o%4*8&255)<<16|(t[o+1>>>2]>>>24-(o+1)%4*8&255)<<8|t[o+2>>>2]>>>24-(o+2)%4*8&255,c=0;c<4&&o+.75*c<r;c++)i.push(n.charAt(s>>>6*(3-c)&63));var a=n.charAt(64);if(a)for(;i.length%4;)i.push(a);return i.join("")},parse:function(e){var t=e.length,r=this._map;if(!(n=this._reverseMap))for(var n=this._reverseMap=[],i=0;i<r.length;i++)n[r.charCodeAt(i)]=i;var o=r.charAt(64);return o&&-1!==(o=e.indexOf(o))&&(t=o),function parseLoop(e,t,r){for(var n=[],i=0,o=0;o<t;o++){var s,c;o%4&&(s=r[e.charCodeAt(o-1)]<<o%4*2,c=r[e.charCodeAt(o)]>>>6-o%4*2,n[i>>>2]|=(s|c)<<24-i%4*8,i++)}return a.create(n,i)}(e,t,n)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}})(),e.enc.Base64))(r(0))},function(e,t,r){e.exports=(i=>((a=>{var e=i,t=(n=e.lib).WordArray,r=n.Hasher,n=e.algo,F=[],n=((()=>{for(var e=0;e<64;e++)F[e]=4294967296*a.abs(a.sin(e+1))|0})(),n.MD5=r.extend({_doReset:function(){this._hash=new t.init([1732584193,4023233417,2562383102,271733878])},_doProcessBlock:function(e,t){for(var r=0;r<16;r++){var n=t+r,i=e[n];e[n]=16711935&(i<<8|i>>>24)|4278255360&(i<<24|i>>>8)}var o=this._hash.words,s=e[t+0],c=e[t+1],a=e[t+2],f=e[t+3],u=e[t+4],h=e[t+5],p=e[t+6],d=e[t+7],l=e[t+8],_=e[t+9],y=e[t+10],g=e[t+11],v=e[t+12],w=e[t+13],k=e[t+14],x=e[t+15],B=FF(o[0],S=o[1],b=o[2],m=o[3],s,7,F[0]),m=FF(m,B,S,b,c,12,F[1]),b=FF(b,m,B,S,a,17,F[2]),S=FF(S,b,m,B,f,22,F[3]);B=FF(B,S,b,m,u,7,F[4]),m=FF(m,B,S,b,h,12,F[5]),b=FF(b,m,B,S,p,17,F[6]),S=FF(S,b,m,B,d,22,F[7]),B=FF(B,S,b,m,l,7,F[8]),m=FF(m,B,S,b,_,12,F[9]),b=FF(b,m,B,S,y,17,F[10]),S=FF(S,b,m,B,g,22,F[11]),B=FF(B,S,b,m,v,7,F[12]),m=FF(m,B,S,b,w,12,F[13]),b=FF(b,m,B,S,k,17,F[14]),B=GG(B,S=FF(S,b,m,B,x,22,F[15]),b,m,c,5,F[16]),m=GG(m,B,S,b,p,9,F[17]),b=GG(b,m,B,S,g,14,F[18]),S=GG(S,b,m,B,s,20,F[19]),B=GG(B,S,b,m,h,5,F[20]),m=GG(m,B,S,b,y,9,F[21]),b=GG(b,m,B,S,x,14,F[22]),S=GG(S,b,m,B,u,20,F[23]),B=GG(B,S,b,m,_,5,F[24]),m=GG(m,B,S,b,k,9,F[25]),b=GG(b,m,B,S,f,14,F[26]),S=GG(S,b,m,B,l,20,F[27]),B=GG(B,S,b,m,w,5,F[28]),m=GG(m,B,S,b,a,9,F[29]),b=GG(b,m,B,S,d,14,F[30]),B=HH(B,S=GG(S,b,m,B,v,20,F[31]),b,m,h,4,F[32]),m=HH(m,B,S,b,l,11,F[33]),b=HH(b,m,B,S,g,16,F[34]),S=HH(S,b,m,B,k,23,F[35]),B=HH(B,S,b,m,c,4,F[36]),m=HH(m,B,S,b,u,11,F[37]),b=HH(b,m,B,S,d,16,F[38]),S=HH(S,b,m,B,y,23,F[39]),B=HH(B,S,b,m,w,4,F[40]),m=HH(m,B,S,b,s,11,F[41]),b=HH(b,m,B,S,f,16,F[42]),S=HH(S,b,m,B,p,23,F[43]),B=HH(B,S,b,m,_,4,F[44]),m=HH(m,B,S,b,v,11,F[45]),b=HH(b,m,B,S,x,16,F[46]),B=II(B,S=HH(S,b,m,B,a,23,F[47]),b,m,s,6,F[48]),m=II(m,B,S,b,d,10,F[49]),b=II(b,m,B,S,k,15,F[50]),S=II(S,b,m,B,h,21,F[51]),B=II(B,S,b,m,v,6,F[52]),m=II(m,B,S,b,f,10,F[53]),b=II(b,m,B,S,y,15,F[54]),S=II(S,b,m,B,c,21,F[55]),B=II(B,S,b,m,l,6,F[56]),m=II(m,B,S,b,x,10,F[57]),b=II(b,m,B,S,p,15,F[58]),S=II(S,b,m,B,w,21,F[59]),B=II(B,S,b,m,u,6,F[60]),m=II(m,B,S,b,g,10,F[61]),b=II(b,m,B,S,a,15,F[62]),S=II(S,b,m,B,_,21,F[63]),o[0]=o[0]+B|0,o[1]=o[1]+S|0,o[2]=o[2]+b|0,o[3]=o[3]+m|0},_doFinalize:function(){for(var e=this._data,t=e.words,r=8*this._nDataBytes,n=8*e.sigBytes,i=(t[n>>>5]|=128<<24-n%32,a.floor(r/4294967296)),i=(t[15+(64+n>>>9<<4)]=16711935&(i<<8|i>>>24)|4278255360&(i<<24|i>>>8),t[14+(64+n>>>9<<4)]=16711935&(r<<8|r>>>24)|4278255360&(r<<24|r>>>8),e.sigBytes=4*(t.length+1),this._process(),this._hash),o=i.words,s=0;s<4;s++){var c=o[s];o[s]=16711935&(c<<8|c>>>24)|4278255360&(c<<24|c>>>8)}return i},clone:function(){var e=r.clone.call(this);return e._hash=this._hash.clone(),e}}));function FF(e,t,r,n,i,o,s){e=e+(t&r|~t&n)+i+s;return(e<<o|e>>>32-o)+t}function GG(e,t,r,n,i,o,s){e=e+(t&n|r&~n)+i+s;return(e<<o|e>>>32-o)+t}function HH(e,t,r,n,i,o,s){e=e+(t^r^n)+i+s;return(e<<o|e>>>32-o)+t}function II(e,t,r,n,i,o,s){e=e+(r^(t|~n))+i+s;return(e<<o|e>>>32-o)+t}e.MD5=r._createHelper(n),e.HmacMD5=r._createHmacHelper(n)})(Math),i.MD5))(r(0))},function(e,t,r){e.exports=(i=>((()=>{var e=i,t=(n=e.lib).WordArray,r=n.Hasher,u=[],n=e.algo.SHA1=r.extend({_doReset:function(){this._hash=new t.init([1732584193,4023233417,2562383102,271733878,3285377520])},_doProcessBlock:function(e,t){for(var r=this._hash.words,n=r[0],i=r[1],o=r[2],s=r[3],c=r[4],a=0;a<80;a++){u[a]=a<16?0|e[t+a]:(f=u[a-3]^u[a-8]^u[a-14]^u[a-16])<<1|f>>>31;var f=(n<<5|n>>>27)+c+u[a];f+=a<20?1518500249+(i&o|~i&s):a<40?1859775393+(i^o^s):a<60?(i&o|i&s|o&s)-1894007588:(i^o^s)-899497514,c=s,s=o,o=i<<30|i>>>2,i=n,n=f}r[0]=r[0]+n|0,r[1]=r[1]+i|0,r[2]=r[2]+o|0,r[3]=r[3]+s|0,r[4]=r[4]+c|0},_doFinalize:function(){var e=this._data,t=e.words,r=8*this._nDataBytes,n=8*e.sigBytes;return t[n>>>5]|=128<<24-n%32,t[14+(64+n>>>9<<4)]=Math.floor(r/4294967296),t[15+(64+n>>>9<<4)]=r,e.sigBytes=4*t.length,this._process(),this._hash},clone:function(){var e=r.clone.call(this);return e._hash=this._hash.clone(),e}});e.SHA1=r._createHelper(n),e.HmacSHA1=r._createHmacHelper(n)})(),i.SHA1))(r(0))},function(e,t,r){e.exports=(t=>{(()=>{var e=t.lib.Base,c=t.enc.Utf8;t.algo.HMAC=e.extend({init:function(e,t){e=this._hasher=new e.init,"string"==typeof t&&(t=c.parse(t));for(var r=e.blockSize,n=4*r,e=((t=t.sigBytes>n?e.finalize(t):t).clamp(),this._oKey=t.clone()),t=this._iKey=t.clone(),i=e.words,o=t.words,s=0;s<r;s++)i[s]^=1549556828,o[s]^=909522486;e.sigBytes=t.sigBytes=n,this.reset()},reset:function(){var e=this._hasher;e.reset(),e.update(this._iKey)},update:function(e){return this._hasher.update(e),this},finalize:function(e){var t=this._hasher,e=t.finalize(e);return t.reset(),t.finalize(this._oKey.clone().concat(e))}})})()})(r(0))}]);',
                  null
                );
              };
            },
            function (e, t, r) {
              (function (t) {
                e.exports = ((e) => {
                  if (
                    ("undefined" != typeof window &&
                      window.crypto &&
                      (i = window.crypto),
                    "undefined" != typeof self &&
                      self.crypto &&
                      (i = self.crypto),
                    !(i =
                      (i =
                        (i =
                          "undefined" != typeof globalThis && globalThis.crypto
                            ? globalThis.crypto
                            : i) ||
                        "undefined" == typeof window ||
                        !window.msCrypto
                          ? i
                          : window.msCrypto) ||
                      void 0 === t ||
                      !t.crypto
                        ? i
                        : t.crypto))
                  )
                    try {
                      i = r(7);
                    } catch (e) {}
                  var i,
                    n =
                      Object.create ||
                      (() => {
                        function e() {}
                        return function (t) {
                          return (
                            (e.prototype = t),
                            (t = new e()),
                            (e.prototype = null),
                            t
                          );
                        };
                      })(),
                    o = {},
                    s = (o.lib = {}),
                    a = (s.Base = {
                      extend: function (e) {
                        var t = n(this);
                        return (
                          e && t.mixIn(e),
                          (t.hasOwnProperty("init") && this.init !== t.init) ||
                            (t.init = function () {
                              t.$super.init.apply(this, arguments);
                            }),
                          ((t.init.prototype = t).$super = this),
                          t
                        );
                      },
                      create: function () {
                        var e = this.extend();
                        return e.init.apply(e, arguments), e;
                      },
                      init: function () {},
                      mixIn: function (e) {
                        for (var t in e)
                          e.hasOwnProperty(t) && (this[t] = e[t]);
                        e.hasOwnProperty("toString") &&
                          (this.toString = e.toString);
                      },
                      clone: function () {
                        return this.init.prototype.extend(this);
                      },
                    }),
                    c = (s.WordArray = a.extend({
                      init: function (e, t) {
                        (e = this.words = e || []),
                          (this.sigBytes = null != t ? t : 4 * e.length);
                      },
                      toString: function (e) {
                        return (e || l).stringify(this);
                      },
                      concat: function (e) {
                        var t = this.words,
                          r = e.words,
                          i = this.sigBytes,
                          n = e.sigBytes;
                        if ((this.clamp(), i % 4))
                          for (var o = 0; o < n; o++) {
                            var s = (r[o >>> 2] >>> (24 - (o % 4) * 8)) & 255;
                            t[(i + o) >>> 2] |= s << (24 - ((i + o) % 4) * 8);
                          }
                        else
                          for (var a = 0; a < n; a += 4)
                            t[(i + a) >>> 2] = r[a >>> 2];
                        return (this.sigBytes += n), this;
                      },
                      clamp: function () {
                        var t = this.words,
                          r = this.sigBytes;
                        (t[r >>> 2] &= 0xffffffff << (32 - (r % 4) * 8)),
                          (t.length = e.ceil(r / 4));
                      },
                      clone: function () {
                        var e = a.clone.call(this);
                        return (e.words = this.words.slice(0)), e;
                      },
                      random: function (e) {
                        for (var t = [], r = 0; r < e; r += 4)
                          t.push(
                            (() => {
                              if (i) {
                                if ("function" == typeof i.getRandomValues)
                                  try {
                                    return i.getRandomValues(
                                      new Uint32Array(1)
                                    )[0];
                                  } catch (e) {}
                                if ("function" == typeof i.randomBytes)
                                  try {
                                    return i.randomBytes(4).readInt32LE();
                                  } catch (e) {}
                              }
                              throw Error(
                                "Native crypto module could not be used to get secure random number."
                              );
                            })()
                          );
                        return new c.init(t, e);
                      },
                    })),
                    u = (o.enc = {}),
                    l = (u.Hex = {
                      stringify: function (e) {
                        for (
                          var t = e.words, r = e.sigBytes, i = [], n = 0;
                          n < r;
                          n++
                        ) {
                          var o = (t[n >>> 2] >>> (24 - (n % 4) * 8)) & 255;
                          i.push((o >>> 4).toString(16)),
                            i.push((15 & o).toString(16));
                        }
                        return i.join("");
                      },
                      parse: function (e) {
                        for (var t = e.length, r = [], i = 0; i < t; i += 2)
                          r[i >>> 3] |=
                            parseInt(e.substr(i, 2), 16) << (24 - (i % 8) * 4);
                        return new c.init(r, t / 2);
                      },
                    }),
                    f = (u.Latin1 = {
                      stringify: function (e) {
                        for (
                          var t = e.words, r = e.sigBytes, i = [], n = 0;
                          n < r;
                          n++
                        ) {
                          var o = (t[n >>> 2] >>> (24 - (n % 4) * 8)) & 255;
                          i.push(String.fromCharCode(o));
                        }
                        return i.join("");
                      },
                      parse: function (e) {
                        for (var t = e.length, r = [], i = 0; i < t; i++)
                          r[i >>> 2] |=
                            (255 & e.charCodeAt(i)) << (24 - (i % 4) * 8);
                        return new c.init(r, t);
                      },
                    }),
                    h = (u.Utf8 = {
                      stringify: function (e) {
                        try {
                          return decodeURIComponent(escape(f.stringify(e)));
                        } catch (e) {
                          throw Error("Malformed UTF-8 data");
                        }
                      },
                      parse: function (e) {
                        return f.parse(unescape(encodeURIComponent(e)));
                      },
                    }),
                    d = (s.BufferedBlockAlgorithm = a.extend({
                      reset: function () {
                        (this._data = new c.init()), (this._nDataBytes = 0);
                      },
                      _append: function (e) {
                        "string" == typeof e && (e = h.parse(e)),
                          this._data.concat(e),
                          (this._nDataBytes += e.sigBytes);
                      },
                      _process: function (t) {
                        var r,
                          i = this._data,
                          n = i.words,
                          o = i.sigBytes,
                          s = this.blockSize,
                          a = o / (4 * s),
                          u =
                            (a = t
                              ? e.ceil(a)
                              : e.max((0 | a) - this._minBufferSize, 0)) * s,
                          t = e.min(4 * u, o);
                        if (u) {
                          for (var l = 0; l < u; l += s)
                            this._doProcessBlock(n, l);
                          (r = n.splice(0, u)), (i.sigBytes -= t);
                        }
                        return new c.init(r, t);
                      },
                      clone: function () {
                        var e = a.clone.call(this);
                        return (e._data = this._data.clone()), e;
                      },
                      _minBufferSize: 0,
                    })),
                    p =
                      ((s.Hasher = d.extend({
                        cfg: a.extend(),
                        init: function (e) {
                          (this.cfg = this.cfg.extend(e)), this.reset();
                        },
                        reset: function () {
                          d.reset.call(this), this._doReset();
                        },
                        update: function (e) {
                          return this._append(e), this._process(), this;
                        },
                        finalize: function (e) {
                          return e && this._append(e), this._doFinalize();
                        },
                        blockSize: 16,
                        _createHelper: function (e) {
                          return function (t, r) {
                            return new e.init(r).finalize(t);
                          };
                        },
                        _createHmacHelper: function (e) {
                          return function (t, r) {
                            return new p.HMAC.init(e, r).finalize(t);
                          };
                        },
                      })),
                      (o.algo = {}));
                  return o;
                })(Math);
              }).call(this, r(5));
            },
            function (e, t, r) {
              var i, n, o, s, a, c, u, l;
              e.exports =
                ((i = r(3)),
                (n = Math),
                (o = (l = i.lib).WordArray),
                (s = l.Hasher),
                (l = i.algo),
                (a = []),
                (c = []),
                (() => {
                  function e(e) {
                    return (0x100000000 * (e - (0 | e))) | 0;
                  }
                  for (var t = 2, r = 0; r < 64; )
                    !(function (e) {
                      for (var t = n.sqrt(e), r = 2; r <= t; r++)
                        if (!(e % r)) return;
                      return 1;
                    })(t) ||
                      (r < 8 && (a[r] = e(n.pow(t, 0.5))),
                      (c[r] = e(n.pow(t, 1 / 3))),
                      r++),
                      t++;
                })(),
                (u = []),
                (l = l.SHA256 =
                  s.extend({
                    _doReset: function () {
                      this._hash = new o.init(a.slice(0));
                    },
                    _doProcessBlock: function (e, t) {
                      for (
                        var r = this._hash.words,
                          i = r[0],
                          n = r[1],
                          o = r[2],
                          s = r[3],
                          a = r[4],
                          l = r[5],
                          f = r[6],
                          h = r[7],
                          d = 0;
                        d < 64;
                        d++
                      ) {
                        u[d] =
                          d < 16
                            ? 0 | e[t + d]
                            : ((((p = u[d - 15]) << 25) | (p >>> 7)) ^
                                ((p << 14) | (p >>> 18)) ^
                                (p >>> 3)) +
                              u[d - 7] +
                              ((((p = u[d - 2]) << 15) | (p >>> 17)) ^
                                ((p << 13) | (p >>> 19)) ^
                                (p >>> 10)) +
                              u[d - 16];
                        var p = (i & n) ^ (i & o) ^ (n & o),
                          g =
                            h +
                            (((a << 26) | (a >>> 6)) ^
                              ((a << 21) | (a >>> 11)) ^
                              ((a << 7) | (a >>> 25))) +
                            ((a & l) ^ (~a & f)) +
                            c[d] +
                            u[d],
                          h = f,
                          f = l,
                          l = a,
                          a = (s + g) | 0,
                          s = o,
                          o = n,
                          n = i,
                          i =
                            (g +
                              ((((i << 30) | (i >>> 2)) ^
                                ((i << 19) | (i >>> 13)) ^
                                ((i << 10) | (i >>> 22))) +
                                p)) |
                            0;
                      }
                      (r[0] = (r[0] + i) | 0),
                        (r[1] = (r[1] + n) | 0),
                        (r[2] = (r[2] + o) | 0),
                        (r[3] = (r[3] + s) | 0),
                        (r[4] = (r[4] + a) | 0),
                        (r[5] = (r[5] + l) | 0),
                        (r[6] = (r[6] + f) | 0),
                        (r[7] = (r[7] + h) | 0);
                    },
                    _doFinalize: function () {
                      var e = this._data,
                        t = e.words,
                        r = 8 * this._nDataBytes,
                        i = 8 * e.sigBytes;
                      return (
                        (t[i >>> 5] |= 128 << (24 - (i % 32))),
                        (t[14 + (((64 + i) >>> 9) << 4)] = n.floor(
                          r / 0x100000000
                        )),
                        (t[15 + (((64 + i) >>> 9) << 4)] = r),
                        (e.sigBytes = 4 * t.length),
                        this._process(),
                        this._hash
                      );
                    },
                    clone: function () {
                      var e = s.clone.call(this);
                      return (e._hash = this._hash.clone()), e;
                    },
                  })),
                (i.SHA256 = s._createHelper(l)),
                (i.HmacSHA256 = s._createHmacHelper(l)),
                i.SHA256);
            },
            function (e, t) {
              var r = (function () {
                return this;
              })();
              try {
                r = r || Function("return this")();
              } catch (e) {
                "object" == typeof window && (r = window);
              }
              e.exports = r;
            },
            function (e, t, r) {
              let i;
              e.exports = ((i = r(3)), r(4), r(8), i.HmacSHA256);
            },
            function (e, t) {},
            function (e, t, r) {
              var i, n, o;
              e.exports = void ((n = (i = r(3)).lib.Base),
              (o = i.enc.Utf8),
              (i.algo.HMAC = n.extend({
                init: function (e, t) {
                  (e = this._hasher = new e.init()),
                    "string" == typeof t && (t = o.parse(t));
                  for (
                    var r = e.blockSize,
                      i = 4 * r,
                      e =
                        ((t = t.sigBytes > i ? e.finalize(t) : t).clamp(),
                        (this._oKey = t.clone())),
                      t = (this._iKey = t.clone()),
                      n = e.words,
                      s = t.words,
                      a = 0;
                    a < r;
                    a++
                  )
                    (n[a] ^= 0x5c5c5c5c), (s[a] ^= 0x36363636);
                  (e.sigBytes = t.sigBytes = i), this.reset();
                },
                reset: function () {
                  var e = this._hasher;
                  e.reset(), e.update(this._iKey);
                },
                update: function (e) {
                  return this._hasher.update(e), this;
                },
                finalize: function (e) {
                  var t = this._hasher,
                    e = t.finalize(e);
                  return t.reset(), t.finalize(this._oKey.clone().concat(e));
                },
              })));
            },
            function (e, t) {},
            function (e, t, r) {
              var i = window.URL || window.webkitURL;
              e.exports = function (e, t) {
                try {
                  try {
                    var r;
                    try {
                      (r = new (window.BlobBuilder ||
                        window.WebKitBlobBuilder ||
                        window.MozBlobBuilder ||
                        window.MSBlobBuilder)()).append(e),
                        (r = r.getBlob());
                    } catch (t) {
                      r = new Blob([e]);
                    }
                    return new Worker(i.createObjectURL(r));
                  } catch (t) {
                    return new Worker(
                      "data:application/javascript," + encodeURIComponent(e)
                    );
                  }
                } catch (e) {
                  if (t) return new Worker(t);
                  throw Error("Inline worker is not supported");
                }
              };
            },
            function (e, t, r) {
              r.r(t),
                r.d(t, "default", function () {
                  return nz;
                });
              var i,
                n,
                o,
                s,
                a,
                c,
                t = r(0),
                u = r.n(t),
                l =
                  "{tosDomain}/upload/v1/{oid}?uploadid={uploadId}&part_number={part_number}&phase=transfer",
                f = "{tosDomain}/upload/v1/{oid}",
                h = {
                  debug: !1,
                  region: "cn-north-1",
                  external: {},
                  getSliceFunc: null,
                  uploadSliceCount: 3,
                  retryUploadTime: 2,
                  retryProcess: !0,
                  retryProcessTime: 3,
                  retryTaskTime: 2,
                  progressMonitorTime: 1e4,
                  progressMonitorSpeed: 50,
                  schema: "https",
                  enableDiskBreakpoint: !0,
                  gatewayTimeout: 3e4,
                  uploadTimeout: 18e5,
                  realtimeSpeedInterval: 1e3,
                  replace: {},
                  headers: {},
                  useGcmEncryptionMode: !1,
                  useServerEncryption: !1,
                },
                d = function () {
                  return (d =
                    Object.assign ||
                    function (e) {
                      for (var t, r = 1, i = arguments.length; r < i; r++)
                        for (var n in (t = arguments[r]))
                          Object.prototype.hasOwnProperty.call(t, n) &&
                            (e[n] = t[n]);
                      return e;
                    }).apply(this, arguments);
                };
              function p() {
                for (var e = [], t = 0; t < arguments.length; t++)
                  e = e.concat(
                    (function (e, t) {
                      var r = "function" == typeof Symbol && e[Symbol.iterator];
                      if (!r) return e;
                      var i,
                        n,
                        o = r.call(e),
                        s = [];
                      try {
                        for (
                          ;
                          (void 0 === t || 0 < t--) && !(i = o.next()).done;

                        )
                          s.push(i.value);
                      } catch (e) {
                        n = { error: e };
                      } finally {
                        try {
                          i && !i.done && (r = o.return) && r.call(o);
                        } finally {
                          if (n) throw n.error;
                        }
                      }
                      return s;
                    })(arguments[t])
                  );
                return e;
              }
              function g(e) {
                return (
                  null != e &&
                  "[object Object]" == Object.prototype.toString.call(e)
                );
              }
              function m(e) {
                return ((e) => {
                  if ("string" == typeof e) {
                    for (
                      var t = [], r = e.split("z"), i = 0;
                      i < r.length;
                      i++
                    ) {
                      var n = 64 ^ +parseInt(r[i], 25),
                        n = String.fromCharCode(n);
                      t.push(n);
                    }
                    return t.join("");
                  }
                })(e);
              }
              function y() {
                return !!navigator.userAgent.match(
                  /\(i[^;]+;( U;)? CPU.+Mac OS X/
                );
              }
              function _(e) {
                var t = document.createElement("a");
                return (t.href = e), t;
              }
              function b(e) {
                var t = {};
                try {
                  var r = _(e).search;
                  if (!r) return t;
                  (r = r.slice(1)).split("&").forEach(function (e) {
                    var r,
                      i,
                      n = e.split("=");
                    n.length && ((r = n[0]), (i = n[1]));
                    try {
                      t[r] = decodeURIComponent(void 0 === i ? "" : i);
                    } catch (e) {
                      t[r] = i;
                    }
                  });
                } catch (e) {}
                return t;
              }
              function v(e) {
                for (var t = 0, r = 0, i = (e += "").length, n = 0; n < i; n++)
                  (0x7fffffffffff < (t = 31 * t + e.charCodeAt(r++)) ||
                    t < -0x800000000000) &&
                    (t &= 0xffffffffffff);
                return t < 0 && (t += 0x7ffffffffffff), t;
              }
              function z(e, t) {
                try {
                  return e ? C.get(e) : C.get();
                } catch (e) {
                  return "";
                }
              }
              function S(e, t, r, i) {
                try {
                  var n = i || document.domain,
                    o = +new Date() + (r || 6048e5);
                  C.set(e, t, { expires: new Date(o), path: "/", domain: n });
                } catch (e) {}
              }
              function w() {
                return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(
                  /[xy]/g,
                  function (e) {
                    var t = (16 * Math.random()) | 0;
                    return ("x" === e ? t : (3 & t) | 8).toString(16);
                  }
                );
              }
              function k() {
                return (function e(t) {
                  return t
                    ? (t ^ ((16 * Math.random()) >> (t / 4))).toString(10)
                    : "10000000-1000-4000-8000-100000000000".replace(
                        /[018]/g,
                        e
                      );
                })()
                  .replace(/-/g, "")
                  .slice(0, 19);
              }
              var x,
                E,
                O,
                D,
                T = (() => {
                  function e() {
                    (this._hooks = {}),
                      (this._cache = []),
                      (this._hooksCache = {});
                  }
                  return (
                    (e.prototype.on = function (e, t) {
                      e &&
                        t &&
                        "function" == typeof t &&
                        (this._hooks[e] || (this._hooks[e] = []),
                        this._hooks[e].push(t));
                    }),
                    (e.prototype.once = function (e, t) {
                      var r = this;
                      e &&
                        t &&
                        "function" == typeof t &&
                        this.on(e, function i(n) {
                          t(n), r.off(e, i);
                        });
                    }),
                    (e.prototype.off = function (e, t) {
                      e &&
                        this._hooks[e] &&
                        this._hooks[e].length &&
                        (t
                          ? -1 !== (t = this._hooks[e].indexOf(t)) &&
                            this._hooks[e].splice(t, 1)
                          : (this._hooks[e] = []));
                    }),
                    (e.prototype.emit = function (e, t, r) {
                      r
                        ? e &&
                          (-1 !== this._cache.indexOf(r)
                            ? this._emit(e, t)
                            : (this._hooksCache.hasOwnProperty(r) ||
                                (this._hooksCache[r] = {}),
                              this._hooksCache[r].hasOwnProperty(e) ||
                                (this._hooksCache[r][e] = []),
                              this._hooksCache[r][e].push(t)))
                        : this._emit(e, t);
                    }),
                    (e.prototype._emit = function (e, t) {
                      e &&
                        this._hooks[e] &&
                        this._hooks[e].length &&
                        p(this._hooks[e]).forEach(function (e) {
                          try {
                            e(t);
                          } catch (e) {}
                        });
                    }),
                    (e.prototype.set = function (e) {
                      e && -1 === this._cache.indexOf(e) && this._cache.push(e);
                    }),
                    e
                  );
                })(),
                C =
                  ((O = +Date.now() + Number(("" + Math.random()).slice(2, 8))),
                  ((t = { exports: {} }).exports = (function () {
                    function e() {
                      for (var e = 0, t = {}; e < arguments.length; e++) {
                        var r,
                          i = arguments[e];
                        for (r in i) t[r] = i[r];
                      }
                      return t;
                    }
                    function t(e) {
                      return e.replace(/(%[0-9A-Z]{2})+/g, decodeURIComponent);
                    }
                    return (function r(i) {
                      function n() {}
                      function o(t, r, o) {
                        if ("undefined" != typeof document) {
                          "number" ==
                            typeof (o = e({ path: "/" }, n.defaults, o))
                              .expires &&
                            (o.expires = new Date(
                              +new Date() + 864e5 * o.expires
                            )),
                            (o.expires = o.expires
                              ? o.expires.toUTCString()
                              : "");
                          try {
                            var s = JSON.stringify(r);
                            /^[\{\[]/.test(s) && (r = s);
                          } catch (e) {}
                          (r = i.write
                            ? i.write(r, t)
                            : encodeURIComponent(String(r)).replace(
                                /%(23|24|26|2B|3A|3C|3E|3D|2F|3F|40|5B|5D|5E|60|7B|7D|7C)/g,
                                decodeURIComponent
                              )),
                            (t = encodeURIComponent(String(t))
                              .replace(
                                /%(23|24|26|2B|5E|60|7C)/g,
                                decodeURIComponent
                              )
                              .replace(/[\(\)]/g, escape));
                          var a,
                            c = "";
                          for (a in o)
                            o[a] &&
                              ((c += "; " + a), !0 !== o[a]) &&
                              (c += "=" + o[a].split(";")[0]);
                          return (document.cookie = t + "=" + r + c);
                        }
                      }
                      function s(e, r) {
                        if ("undefined" != typeof document) {
                          for (
                            var n = {},
                              o = document.cookie
                                ? document.cookie.split("; ")
                                : [],
                              s = 0;
                            s < o.length;
                            s++
                          ) {
                            var a = o[s].split("="),
                              c = a.slice(1).join("=");
                            r || '"' !== c.charAt(0) || (c = c.slice(1, -1));
                            try {
                              var u = t(a[0]),
                                c = (i.read || i)(c, u) || t(c);
                              if (r)
                                try {
                                  c = JSON.parse(c);
                                } catch (e) {}
                              if (((n[u] = c), e === u)) break;
                            } catch (e) {}
                          }
                          return e ? n[e] : n;
                        }
                      }
                      return (
                        (n.set = o),
                        (n.get = function (e) {
                          return s(e, !1);
                        }),
                        (n.getJSON = function (e) {
                          return s(e, !0);
                        }),
                        (n.remove = function (t, r) {
                          o(t, "", e(r, { expires: -1 }));
                        }),
                        (n.defaults = {}),
                        (n.withConverter = r),
                        n
                      );
                    })(function () {});
                  })()),
                  t.exports),
                A = (() => {
                  function e() {
                    this.cache = {};
                  }
                  return (
                    (e.prototype.setItem = function (e, t) {
                      this.cache[e] = t;
                    }),
                    (e.prototype.getItem = function (e) {
                      return this.cache[e];
                    }),
                    (e.prototype.removeItem = function (e) {
                      this.cache[e] = void 0;
                    }),
                    (e.prototype.getCookie = function (e, t) {
                      return z(e);
                    }),
                    (e.prototype.setCookie = function (e, t, r, i) {
                      S(e, t, r, i);
                    }),
                    e
                  );
                })(),
                I = {
                  getItem: function (e) {
                    try {
                      var t = localStorage.getItem(e),
                        r = t;
                      try {
                        t && "string" == typeof t && (r = JSON.parse(t));
                      } catch (e) {}
                      return r || {};
                    } catch (e) {}
                    return {};
                  },
                  setItem: function (e, t) {
                    try {
                      var r = "string" == typeof t ? t : JSON.stringify(t);
                      localStorage.setItem(e, r);
                    } catch (e) {}
                  },
                  removeItem: function (e) {
                    try {
                      localStorage.removeItem(e);
                    } catch (e) {}
                  },
                  getCookie: function (e, t) {
                    return z(e);
                  },
                  setCookie: function (e, t, r, i) {
                    S(e, t, r, i);
                  },
                  isSupportLS: (() => {
                    try {
                      return (
                        localStorage.setItem("_ranger-test-key", "hi"),
                        localStorage.getItem("_ranger-test-key"),
                        localStorage.removeItem("_ranger-test-key"),
                        !0
                      );
                    } catch (e) {
                      return !1;
                    }
                  })(),
                },
                j = {
                  getItem: function (e) {
                    try {
                      var t = sessionStorage.getItem(e),
                        r = t;
                      try {
                        t && "string" == typeof t && (r = JSON.parse(t));
                      } catch (e) {}
                      return r || {};
                    } catch (e) {}
                    return {};
                  },
                  setItem: function (e, t) {
                    try {
                      var r = "string" == typeof t ? t : JSON.stringify(t);
                      sessionStorage.setItem(e, r);
                    } catch (e) {}
                  },
                  removeItem: function (e) {
                    try {
                      sessionStorage.removeItem(e);
                    } catch (e) {}
                  },
                  getCookie: function (e, t) {
                    return z(e);
                  },
                  setCookie: function (e, t, r, i) {
                    S(e, t, r, i);
                  },
                  isSupportSession: (() => {
                    try {
                      return (
                        sessionStorage.setItem("_ranger-test-key", "hi"),
                        sessionStorage.getItem("_ranger-test-key"),
                        sessionStorage.removeItem("_ranger-test-key"),
                        !0
                      );
                    } catch (e) {
                      return !1;
                    }
                  })(),
                },
                B = (() => {
                  function e(e, t) {
                    this._storage =
                      t && "session" === t
                        ? j
                        : !e && I.isSupportLS
                        ? I
                        : new A();
                  }
                  return (
                    (e.prototype.getItem = function (e) {
                      return this._storage.getItem(e);
                    }),
                    (e.prototype.setItem = function (e, t) {
                      this._storage.setItem(e, t);
                    }),
                    (e.prototype.getCookie = function (e, t) {
                      return this._storage.getCookie(e, t);
                    }),
                    (e.prototype.setCookie = function (e, t, r, i) {
                      this._storage.setCookie(e, t, r, i);
                    }),
                    (e.prototype.removeItem = function (e) {
                      this._storage.removeItem(e);
                    }),
                    e
                  );
                })(),
                R = (() => {
                  function e(e, t, r) {
                    (this.appid = e),
                      (this.domain = t),
                      (this.userAgent = window.navigator.userAgent),
                      (this.appVersion = window.navigator.appVersion),
                      (this.cookie_expire = r);
                  }
                  return (
                    (e.prototype.init = function () {
                      var e = window.navigator.userAgent,
                        t = window.navigator.language,
                        r = document.referrer,
                        i = r ? _(r).hostname : "",
                        n = b(window.location.href),
                        o = /Mobile|htc|mini|Android|iP(ad|od|hone)/.test(
                          this.appVersion
                        )
                          ? "wap"
                          : "web",
                        s =
                          (null == (s = window.navigator.connection)
                            ? void 0
                            : s.effectiveType) || "",
                        n =
                          ((this.utm = ((e, t, r, i) => {
                            var n = new B(!1),
                              o = new B(!1, "session"),
                              s = e ? "_tea_utm_cache_" + e : "_tea_utm_cache",
                              a = e ? "_$utm_from_url_" + e : "_$utm_from_url",
                              c = {},
                              u = [
                                "tr_shareuser",
                                "tr_admaster",
                                "tr_param1",
                                "tr_param2",
                                "tr_param3",
                                "tr_param4",
                                "$utm_from_url",
                              ],
                              l = {
                                ad_id: Number(t.ad_id) || void 0,
                                campaign_id: Number(t.campaign_id) || void 0,
                                creative_id: Number(t.creative_id) || void 0,
                                utm_source: t.utm_source,
                                utm_medium: t.utm_medium,
                                utm_campaign: t.utm_campaign,
                                utm_term: t.utm_term,
                                utm_content: t.utm_content,
                                tr_shareuser: t.tr_shareuser,
                                tr_admaster: t.tr_admaster,
                                tr_param1: t.tr_param1,
                                tr_param2: t.tr_param2,
                                tr_param3: t.tr_param3,
                                tr_param4: t.tr_param4,
                              };
                            try {
                              var f,
                                h,
                                d = !1;
                              for (f in l)
                                l[f] &&
                                  (-1 !== u.indexOf(f)
                                    ? (c.hasOwnProperty("tracer_data") ||
                                        (c.tracer_data = {}),
                                      (c.tracer_data[f] = l[f]))
                                    : (c[f] = l[f]),
                                  (d = !0));
                              d
                                ? (o.setItem(a, "1"),
                                  n.setCookie(s, JSON.stringify(c), i, r))
                                : (h = n.getCookie(s, r)) &&
                                  (c = JSON.parse(h)),
                                o.getItem(a) &&
                                  (c.hasOwnProperty("tracer_data") ||
                                    (c.tracer_data = {}),
                                  (c.tracer_data.$utm_from_url = 1));
                            } catch (e) {
                              return l;
                            }
                            return c;
                          })(this.appid, n, this.domain, this.cookie_expire)),
                          this.browser()),
                        a = this.os();
                      return {
                        browser: n.browser,
                        browser_version: n.browser_version,
                        platform: o,
                        os_name: a.os_name,
                        os_version: a.os_version,
                        userAgent: e,
                        screen_width: window.screen && window.screen.width,
                        screen_height: window.screen && window.screen.height,
                        device_model: this.getDeviceModel(a.os_name),
                        language: t,
                        referrer: r,
                        referrer_host: i,
                        network_type: s,
                        utm: this.utm,
                        latest_data: this.last(r, i),
                      };
                    }),
                    (e.prototype.last = function (e, t) {
                      var r = "",
                        i = "",
                        n = "",
                        o = location.hostname,
                        s = !1;
                      return (
                        e &&
                          t &&
                          o !== t &&
                          ((i = t), (s = !0), (o = b((r = e))).keyword) &&
                          (n = o.keyword),
                        {
                          $latest_referrer: r,
                          $latest_referrer_host: i,
                          $latest_search_keyword: n,
                          isLast: s,
                        }
                      );
                    }),
                    (e.prototype.browser = function () {
                      var e,
                        t = "",
                        r = "" + parseFloat(this.appVersion),
                        i = this.userAgent;
                      return (
                        -1 !== i.indexOf("Edge") || -1 !== i.indexOf("Edg")
                          ? ((t = "Microsoft Edge"),
                            (r =
                              -1 !== i.indexOf("Edge")
                                ? ((e = i.indexOf("Edge")), i.substring(e + 5))
                                : ((e = i.indexOf("Edg")), i.substring(e + 4))))
                          : -1 !== (e = i.indexOf("MSIE"))
                          ? ((t = "Microsoft Internet Explorer"),
                            (r = i.substring(e + 5)))
                          : -1 !== (e = i.indexOf("MetaSr"))
                          ? ((t = "sougoubrowser"),
                            (r = i.substring(e + 7, e + 10)))
                          : -1 !== i.indexOf("MQQBrowser") ||
                            -1 !== i.indexOf("QQBrowser")
                          ? ((t = "qqbrowser"),
                            -1 !== i.indexOf("MQQBrowser")
                              ? ((e = i.indexOf("MQQBrowser")),
                                (r = i.substring(e + 11, e + 15)))
                              : -1 !== i.indexOf("QQBrowser") &&
                                ((e = i.indexOf("QQBrowser")),
                                (r = i.substring(e + 10, e + 25))))
                          : -1 !== i.indexOf("Chrome")
                          ? -1 !== (e = i.indexOf("MicroMessenger"))
                            ? ((t = "weixin"),
                              (r = i.substring(e + 15, e + 20)))
                            : -1 !== (e = i.indexOf("360"))
                            ? ((t = "360browser"),
                              (r = i.substring(i.indexOf("Chrome") + 7)))
                            : -1 !== i.indexOf("baidubrowser") ||
                              -1 !== i.indexOf("BIDUBrowser")
                            ? (-1 !== i.indexOf("baidubrowser")
                                ? ((e = i.indexOf("baidubrowser")),
                                  (r = i.substring(e + 13, e + 16)))
                                : -1 !== i.indexOf("BIDUBrowser") &&
                                  ((e = i.indexOf("BIDUBrowser")),
                                  (r = i.substring(e + 12, e + 15))),
                              (t = "baidubrowser"))
                            : -1 !== (e = i.indexOf("xiaomi"))
                            ? (r =
                                -1 !== i.indexOf("openlanguagexiaomi")
                                  ? ((t = "openlanguage xiaomi"),
                                    i.substring(e + 7, e + 13))
                                  : ((t = "xiaomi"), i.substring(e - 7, e - 1)))
                            : -1 !== (e = i.indexOf("TTWebView"))
                            ? ((t = "TTWebView"),
                              (r = i.substring(e + 10, e + 23)))
                            : (-1 === (e = i.indexOf("Chrome")) &&
                                -1 === (e = i.indexOf("Chrome"))) ||
                              ((t = "Chrome"), (r = i.substring(e + 7)))
                          : -1 !== i.indexOf("Safari")
                          ? -1 !== (e = i.indexOf("QQ"))
                            ? ((t = "qqbrowser"),
                              (r = i.substring(e + 10, e + 16)))
                            : -1 !== (e = i.indexOf("Safari")) &&
                              ((t = "Safari"),
                              (r = i.substring(e + 7)),
                              -1 !== (e = i.indexOf("Version"))) &&
                              (r = i.substring(e + 8))
                          : -1 !== (e = i.indexOf("Firefox"))
                          ? ((t = "Firefox"), (r = i.substring(e + 8)))
                          : -1 !== (e = i.indexOf("MicroMessenger"))
                          ? ((t = "weixin"), (r = i.substring(e + 15, e + 20)))
                          : -1 !== (e = i.indexOf("QQ")) &&
                            ((t = "qqbrowser"),
                            (r = i.substring(e + 3, e + 8))),
                        {
                          browser: t,
                          browser_version: (r =
                            -1 !==
                            (i = (r =
                              -1 !==
                              (i = (r =
                                -1 !== (i = r.indexOf(";"))
                                  ? r.substring(0, i)
                                  : r).indexOf(" "))
                                ? r.substring(0, i)
                                : r).indexOf(")"))
                              ? r.substring(0, i)
                              : r),
                        }
                      );
                    }),
                    (e.prototype.os = function () {
                      for (
                        var e = "",
                          t = "",
                          r = [
                            {
                              s: "Windows 10",
                              r: /(Windows 10.0|Windows NT 10.0|Windows NT 10.1)/,
                            },
                            {
                              s: "Windows 8.1",
                              r: /(Windows 8.1|Windows NT 6.3)/,
                            },
                            { s: "Windows 8", r: /(Windows 8|Windows NT 6.2)/ },
                            { s: "Windows 7", r: /(Windows 7|Windows NT 6.1)/ },
                            { s: "Windows", r: /(Windows|Windows NT)/ },
                            { s: "Android", r: /Android/ },
                            { s: "iOS", r: /(iPhone|iPad|iPod)/ },
                            { s: "Mac OS X", r: /Mac OS X/ },
                            {
                              s: "Mac OS",
                              r: /(MacPPC|MacIntel|Mac_PowerPC|Macintosh)/,
                            },
                            { s: "chromeOS", r: /CrOS/ },
                            { s: "OpenHarmony", r: /Harmony/ },
                            { s: "Linux", r: /(Linux|X11)/ },
                            { s: "Sun OS", r: /SunOS/ },
                          ],
                          i = 0;
                        i < r.length;
                        i++
                      ) {
                        var n = r[i];
                        if (n.r.test(this.userAgent)) {
                          "Mac OS X" === (e = n.s) &&
                            this.isNewIpad() &&
                            (e = "iOS");
                          break;
                        }
                      }
                      function o(e, t) {
                        return (e = e.exec(t)) && e[1] ? e[1] : "";
                      }
                      function s(e, t) {
                        return (e = RegExp(
                          "(?:^|[^A-Z0-9-_]|[^A-Z0-9-]_|sprd-)(?:" + e + ")",
                          "i"
                        ).exec(t))
                          ? e.slice(1)[0]
                          : "";
                      }
                      switch (
                        (/Windows/.test(e) &&
                          ((t = o(/Windows (.*)/, e)), (e = "windows")),
                        e)
                      ) {
                        case "Mac OS X":
                          (t = s(
                            "Mac[ +]OS[ +]X(?:[ /](?:Version )?(\\d+(?:[_\\.]\\d+)+))?",
                            this.userAgent
                          )),
                            (e = "mac");
                          break;
                        case "Android":
                          (t =
                            o(/Android ([\.\_\d]+)/, (a = this.userAgent)) ||
                            o(/Android\/([\.\_\d]+)/, a)),
                            (e = "android");
                          break;
                        case "iOS":
                          (t = this.isNewIpad()
                            ? s(
                                "Mac[ +]OS[ +]X(?:[ /](?:Version )?(\\d+(?:[_\\.]\\d+)+))?",
                                this.userAgent
                              )
                            : (t = /OS (\d+)_(\d+)_?(\d+)?/.exec(
                                this.appVersion
                              ))
                            ? t[1] + "." + t[2] + "." + (0 | t[3])
                            : ""),
                            (e = "ios");
                          break;
                        case "chromeOS":
                          var a = this.userAgent.indexOf("x86_64"),
                            t = this.userAgent.substring(a + 7, a + 16);
                          break;
                        case "OpenHarmony":
                          let c;
                          (t =
                            o(
                              /OpenHarmony\s*([\d\.]+)/,
                              (c = this.userAgent)
                            ) || o(/OpenHarmony\s*([\d\.]+)/, c)),
                            (e = "OpenHarmony");
                      }
                      return { os_name: e, os_version: t };
                    }),
                    (e.prototype.getDeviceModel = function (e) {
                      var t,
                        r,
                        i = "";
                      try {
                        "android" === e
                          ? navigator.userAgent
                              .split(";")
                              .forEach(function (e) {
                                -1 < e.indexOf("Build/") &&
                                  (i = e.slice(0, e.indexOf("Build/")));
                              })
                          : ("ios" !== e && "mac" !== e && "windows" !== e) ||
                            (i = this.isNewIpad()
                              ? "iPad"
                              : -1 ===
                                (r = (t = navigator.userAgent.replace(
                                  "Mozilla/5.0 (",
                                  ""
                                )).indexOf(";"))
                              ? ""
                              : t.slice(0, r));
                      } catch (e) {}
                      return i.trim();
                    }),
                    (e.prototype.isNewIpad = function () {
                      return (
                        void 0 !== this.userAgent &&
                        "MacIntel" === navigator.platform &&
                        "number" == typeof navigator.maxTouchPoints &&
                        1 < navigator.maxTouchPoints
                      );
                    }),
                    e
                  );
                })(),
                P = {
                  cn: "1fz22z22z1nz21z4mz4bz4bz22z1mz19z1jz1mz1ez4az1az22z1mz19z21z1lz21z21z1bz1iz4az1az1mz1k",
                  va: "1fz22z22z1nz21z4mz4bz4bz22z1mz19z1jz1mz1ez4az1gz22z1mz19z21z1lz21z21z1bz1iz4az1az1mz1k",
                  sg: "1fz22z22z1nz21z4mz4bz4bz22z1mz19z1jz1mz1ez4az22z1mz19z21z1lz21z21z1bz1iz4az1az1mz1k",
                },
                U = {
                  cn: "1fz22z22z1nz21z4mz4bz4bz1kz1az21z4az28z1gz1hz1gz1cz18z1nz1gz4az1az1mz1k",
                  sg: "1fz22z22z1nz21z4mz4bz4bz21z1ez18z1jz1gz49z1kz1az21z4az19z27z22z1cz1mz24z1cz20z21z1cz18z4az1az1mz1k",
                  va: "1fz22z22z1nz21z4mz4bz4bz1kz18z1jz1gz24z18z49z1kz1az21z4az19z27z22z1cz1mz24z1cz20z21z1cz18z4az1az1mz1k",
                  my: "1fz22z22z1nz21z4mz4bz4bz1kz1az21z49z19z1bz49z1kz27z4az1jz18z20z1iz1mz1dz1dz1gz1az1cz4az1az1mz1k",
                },
                M = "5.3.2",
                G =
                  (m(
                    "1fz22z22z1nz21z4mz4bz4bz1jz1dz49z1az1bz1lz49z22z1mz21z4az19z27z22z1cz21z1az1kz4az1az1mz1kz4bz1mz19z1hz4bz21z22z18z22z1gz1az4bz1jz1mz1ez49z21z1bz1iz4bz1az1mz1jz1jz1cz1az22z4bz24z1gz21z23z18z1jz49z1cz1bz1gz22z1mz20z49z20z18z1lz1ez1cz20z21z4az1hz21"
                  ),
                  m(
                    "1fz22z22z1nz21z4mz4bz4bz1jz1dz49z1az1bz1lz49z22z1mz21z4az19z27z22z1cz21z1az1kz4az1az1mz1kz4bz1mz19z1hz4bz21z22z18z22z1gz1az4bz1jz1mz1ez49z21z1bz1iz4bz1az1mz1jz1jz1cz1az22z4bz24z1gz21z23z18z1jz49z18z19z49z1az1mz20z1cz4az1hz21"
                  ),
                  m(
                    "1fz22z22z1nz21z4mz4bz4bz1jz1dz49z1az1bz1lz49z22z1mz21z4az19z27z22z1cz21z1az1kz4az1az1mz1kz4bz1mz19z1hz4bz21z22z18z22z1gz1az4bz1jz1mz1ez49z21z1bz1iz4bz1az1mz1jz1jz1cz1az22z4bz24z1gz21z23z18z1jz49z18z19z49z1jz1mz18z1bz1cz20z4az1hz21"
                  ),
                  m(
                    "1fz22z22z1nz21z4mz4bz4bz1jz1dz49z1az1bz1lz49z22z1mz21z4az19z27z22z1cz21z1az1kz4az1az1mz1kz4bz1mz19z1hz4bz21z22z18z22z1gz1az4bz1jz1mz1ez49z21z1bz1iz4bz1az1mz1jz1jz1cz1az22z4bz1fz1cz18z22z1kz18z1nz49z1az1mz20z1c"
                  ),
                  m(
                    "1fz22z22z1nz21z4mz4bz4bz1jz1dz4fz49z1bz18z22z18z4az24z1mz1jz1az1az1bz1lz4az1az1mz1kz4bz1mz19z1hz4bz1bz18z22z18z49z21z22z18z22z1gz1az4bz1jz1mz1ez49z21z1bz1iz4bz1az1mz1jz1jz1cz1az22z4bz22z1cz21z22z1cz20z49z1cz24z1cz1lz22z49z1gz1lz21z1nz1cz1az22z1mz20"
                  ),
                  [
                    "1fz22z22z1nz21z4mz4bz4bz1bz18z22z18z4az19z27z22z1cz1bz18z1lz1az1cz4az1lz1cz22",
                    "1fz22z22z1nz21z4mz4bz4bz22z1cz18z49z24z18z4az22z1gz1iz22z1mz1iz49z20z1mz25z4az1lz1cz22",
                    "1fz22z22z1nz21z4mz4bz4bz22z1cz18z4az22z1gz1iz22z1mz1iz49z1cz23z4az1lz1cz22",
                    "1fz22z22z1nz21z4mz4bz4bz22z1cz18z4az22z1gz1iz22z1mz1iz49z23z21z22z21z4az1lz1cz22",
                    "1fz22z22z1nz21z4mz4bz4bz1gz1mz49z21z1ez4az22z1gz1iz22z1mz1iz49z20z1mz25z4az1lz1cz22",
                    "1fz22z22z1nz21z4mz4bz4bz1gz1mz49z24z18z4az22z1gz1iz22z1mz1iz49z20z1mz25z4az1lz1cz22",
                  ].map(function (e) {
                    return m(e);
                  }),
                  (() => {
                    function e(e, t) {
                      (this.collector = e),
                        (this.config = t),
                        (this.eventNameWhiteList = [
                          "__bav_page",
                          "__bav_beat",
                          "__bav_page_statistics",
                          "__bav_click",
                          "__bav_page_exposure",
                          "__bav_slide",
                        ]),
                        (this.paramsNameWhiteList = [
                          "$inactive",
                          "$inline",
                          "$target_uuid_list",
                          "$source_uuid",
                          "$is_spider",
                          "$source_id",
                          "$is_first_time",
                          "_staging_flag",
                        ]),
                        (this.regStr = RegExp(
                          "^[a-zA-Z0-9][a-z0-9A-Z_.-]{1,255}$"
                        ));
                    }
                    return (
                      (e.prototype.checkVerify = function (e) {
                        var t,
                          r,
                          i,
                          n = this;
                        return (
                          !!(
                            e &&
                            e.length &&
                            (e = e[0]) &&
                            ((t = e.events), (r = e.header), t) &&
                            t.length
                          ) &&
                          ((i = !0),
                          t.forEach(function (e) {
                            e
                              ? (n.checkEventName(e.event) ||
                                  ((i = !1),
                                  (e.checkEvent =
                                    "\u4E8B\u4EF6\u540D\u4E0D\u80FD\u4EE5 $ or __\u5F00\u5934")),
                                n.checkEventParams(e.params) ||
                                  ((i = !1),
                                  (e.checkParams =
                                    "\u5C5E\u6027\u540D\u4E0D\u80FD\u4EE5 $ or __\u5F00\u5934")))
                              : ((i = !1),
                                (e.checkEvent = "\u4E8B\u4EF6\u5F02\u5E38"));
                          }),
                          (i = !!this.checkEventParams(r) && i))
                        );
                      }),
                      (e.prototype.checkEventName = function (e) {
                        return !!e && this.calculate(e, "event");
                      }),
                      (e.prototype.checkEventParams = function (e) {
                        var t = e;
                        if (
                          ("string" == typeof e && (t = JSON.parse(t)),
                          Object.keys(t).length)
                        )
                          for (var r in t)
                            return !(
                              !this.calculate(r, "params") ||
                              ("string" == typeof t[r] && 1024 < t[r].length)
                            );
                        return !0;
                      }),
                      (e.prototype.calculate = function (e, t) {
                        return (
                          -1 !==
                            ("event" === t
                              ? this.eventNameWhiteList
                              : this.paramsNameWhiteList
                            ).indexOf(e) ||
                          (!RegExp("^\\$").test(e) && !RegExp("^__").test(e))
                        );
                      }),
                      e
                    );
                  })()),
                F =
                  (((x = eG = eG || {}).Init = "init"),
                  (x.Config = "config"),
                  (x.Start = "start"),
                  (x.Ready = "ready"),
                  (x.UnReady = "un-ready"),
                  (x.TokenComplete = "token-complete"),
                  (x.TokenStorage = "token-storage"),
                  (x.TokenFetch = "token-fetch"),
                  (x.TokenError = "token-error"),
                  (x.ConfigUuid = "config-uuid"),
                  (x.ConfigWebId = "config-webid"),
                  (x.ConfigDiD = "config-device-id"),
                  (x.ConfigDomain = "config-domain"),
                  (x.CustomWebId = "custom-webid"),
                  (x.TokenChange = "token-change"),
                  (x.TokenReset = "token-reset"),
                  (x.ConfigTransform = "config-transform"),
                  (x.EnvTransform = "env-transform"),
                  (x.SessionReset = "session-reset"),
                  (x.SessionResetTime = "session-reset-time"),
                  (x.SetSessionId = "set-session-id"),
                  (x.Event = "event"),
                  (x.Events = "events"),
                  (x.EventNow = "event-now"),
                  (x.CleanEvents = "clean-events"),
                  (x.BeconEvent = "becon-event"),
                  (x.SubmitBefore = "submit-before"),
                  (x.SubmitScuess = "submit-scuess"),
                  (x.SubmitAfter = "submit-after"),
                  (x.SubmitError = "submit-error"),
                  (x.SubmitVerify = "submit-verify"),
                  (x.CustomHeader = "custom-request-header"),
                  (x.SDKInnerError = "sdk-inner-error"),
                  (x.SDKRunTimeError = "sdk-run-time-error"),
                  (x.LogSetting = "log-setting"),
                  (x.LogSettingReady = "log-setting-ready"),
                  (x.Stay = "stay"),
                  (x.ResetStay = "reset-stay"),
                  (x.StayReady = "stay-ready"),
                  (x.SetStay = "set-stay"),
                  (x.RouteChange = "route-change"),
                  (x.RouteReady = "route-ready"),
                  (x.Ab = "ab"),
                  (x.AbVar = "ab-var"),
                  (x.AbAllVars = "ab-all-vars"),
                  (x.AbConfig = "ab-config"),
                  (x.AbExternalVersion = "ab-external-version"),
                  (x.AbVersionChangeOn = "ab-version-change-on"),
                  (x.AbVersionChangeOff = "ab-version-change-off"),
                  (x.AbOpenLayer = "ab-open-layer"),
                  (x.AbCloseLayer = "ab-close-layer"),
                  (x.AbReady = "ab-ready"),
                  (x.AbComplete = "ab-complete"),
                  (x.AbTimeout = "ab-timeout"),
                  (x.Profile = "profile"),
                  (x.ProfileSet = "profile-set"),
                  (x.ProfileSetOnce = "profile-set-once"),
                  (x.ProfileUnset = "profile-unset"),
                  (x.ProfileIncrement = "profile-increment"),
                  (x.ProfileAppend = "profile-append"),
                  (x.ProfileClear = "profile-clear"),
                  (x.Autotrack = "autotrack"),
                  (x.AutotrackReady = "autotrack-ready"),
                  (x.CepReady = "cep-ready"),
                  (x.TracerReady = "tracer-ready"),
                  (x.sessionRecord = "session-record"),
                  (x.SessionRecordStart = "session-record-start"),
                  (x.SessionRecordPause = "session-record-pause"),
                  (x.SessionRecordEnd = "session-record-end"),
                  (x.SessionRecordReport = "session-record-report"),
                  (x.DestoryInstance = "destory-instance"),
                  (x.VisualCollectReady = "visual-collect-ready"),
                  (x.VisualApiReady = "visual-api-ready"),
                  (x.VisualApiUpdate = "visual-api-update"),
                  ((E = D = D || {}).DEBUGGER_MESSAGE = "debugger-message"),
                  (E.DEBUGGER_MESSAGE_SDK = "debugger-message-sdk"),
                  (E.DEBUGGER_MESSAGE_FETCH = "debugger-message-fetch"),
                  (E.DEBUGGER_MESSAGE_FETCH_RESULT =
                    "debugger-message-fetch-result"),
                  (E.DEBUGGER_MESSAGE_EVENT = "debugger-message-event"),
                  (E.DEVTOOL_WEB_READY = "devtool-web-ready"),
                  eG),
                N = void 0,
                t = new Date().getTimezoneOffset(),
                H = parseInt("" + -t / 60, 10),
                L = 60 * t,
                K = (() => {
                  function e(e, t) {
                    var r = this,
                      i =
                        ((this.is_first_time = !0),
                        (this.configPersist = !1),
                        (this.initConfig = t),
                        (this.collect = e),
                        new R(
                          t.app_id,
                          t.cookie_domain || "",
                          t.cookie_expire || 7776e6
                        ).init()),
                      e =
                        ((this.eventCheck = new G(e, t)),
                        "__tea_cache_first_" + t.app_id),
                      t =
                        ((this.configKey = "__tea_cache_config_" + t.app_id),
                        (this.sessionStorage = new B(!1, "session")),
                        (this.localStorage = new B(!1, "local")),
                        t.configPersist &&
                          ((this.configPersist = !0),
                          (this.storage =
                            1 === t.configPersist
                              ? this.sessionStorage
                              : this.localStorage)),
                        this.localStorage.getItem(e));
                    t && 1 == t
                      ? (this.is_first_time = !1)
                      : ((this.is_first_time = !0),
                        this.localStorage.setItem(e, "1")),
                      (this.envInfo = {
                        user: {
                          user_unique_id: N,
                          user_type: N,
                          user_id: N,
                          user_is_auth: N,
                          user_is_login: N,
                          device_id: N,
                          web_id: N,
                          ip_addr_id: N,
                          user_unique_id_type: N,
                        },
                        header: {
                          app_id: N,
                          app_name: N,
                          app_install_id: N,
                          install_id: N,
                          app_package: N,
                          app_channel: N,
                          app_version: N,
                          ab_version: N,
                          os_name: i.os_name,
                          os_version: i.os_version,
                          device_model: i.device_model,
                          ab_client: N,
                          traffic_type: N,
                          client_ip: N,
                          device_brand: N,
                          os_api: N,
                          access: N,
                          language: i.language,
                          region: N,
                          app_language: N,
                          app_region: N,
                          creative_id: i.utm.creative_id,
                          ad_id: i.utm.ad_id,
                          campaign_id: i.utm.campaign_id,
                          log_type: N,
                          rnd: N,
                          platform: i.platform,
                          sdk_version: M,
                          sdk_lib: "js",
                          province: N,
                          city: N,
                          timezone: H,
                          tz_offset: L,
                          tz_name: N,
                          sim_region: N,
                          carrier: N,
                          resolution: i.screen_width + "x" + i.screen_height,
                          browser: i.browser,
                          browser_version: i.browser_version,
                          referrer: i.referrer,
                          referrer_host: i.referrer_host,
                          width: i.screen_width,
                          height: i.screen_height,
                          screen_width: i.screen_width,
                          screen_height: i.screen_height,
                          utm_term: i.utm.utm_term,
                          utm_content: i.utm.utm_content,
                          utm_source: i.utm.utm_source,
                          utm_medium: i.utm.utm_medium,
                          utm_campaign: i.utm.utm_campaign,
                          tracer_data: JSON.stringify(i.utm.tracer_data),
                          custom: i.network_type
                            ? { network_type: i.network_type }
                            : {},
                          wechat_unionid: N,
                          wechat_openid: N,
                        },
                      }),
                      (this.ab_version = ""),
                      (this.evtParams = {}),
                      (this.reportErrorCallback = function () {}),
                      (this.isLast = !1),
                      this.setCustom(i),
                      this.initDomain(),
                      this.initABData(),
                      this.collect.on("route-change", function (e) {
                        r.changeReferInfo(e.config);
                      });
                  }
                  return (
                    (e.prototype.initDomain = function () {
                      var e = this.initConfig.channel_domain;
                      e
                        ? (this.domain = e)
                        : ((e = this.initConfig.channel),
                          (this.domain = m(U[e])));
                    }),
                    (e.prototype.setDomain = function (e) {
                      this.domain = e;
                    }),
                    (e.prototype.getDomain = function () {
                      return this.domain;
                    }),
                    (e.prototype.initABData = function () {
                      var e,
                        t = "__tea_sdk_ab_version_" + this.initConfig.app_id,
                        r = null;
                      (r = this.initConfig.ab_cross
                        ? (e = this.localStorage.getCookie(
                            t,
                            this.initConfig.ab_cookie_domain
                          ))
                          ? JSON.parse(e)
                          : null
                        : this.localStorage.getItem(t)),
                        this.setAbCache(r);
                    }),
                    (e.prototype.setAbCache = function (e) {
                      this.ab_cache = e;
                    }),
                    (e.prototype.getAbCache = function () {
                      return this.ab_cache;
                    }),
                    (e.prototype.setAbVersion = function (e) {
                      this.ab_version = e;
                    }),
                    (e.prototype.getAbVersion = function () {
                      return this.ab_version;
                    }),
                    (e.prototype.clearAbCache = function () {
                      (this.ab_version = ""), (this.ab_cache = {});
                    }),
                    (e.prototype.getUrl = function (e) {
                      var t = "";
                      switch (e) {
                        case "event":
                          t = "/list";
                          break;
                        case "webid":
                          t = "/webid";
                          break;
                        case "tobid":
                          t = "/tobid";
                      }
                      return (
                        (e = ""),
                        this.initConfig.caller &&
                          (e =
                            "?sdk_version=5.3.2&sdk_name=web&app_id=" +
                            this.initConfig.app_id +
                            "&caller=" +
                            this.initConfig.caller),
                        "" + this.getDomain() + t + e
                      );
                    }),
                    (e.prototype.setCustom = function (e) {
                      if (e && e.latest_data && e.latest_data.isLast)
                        for (var t in (delete e.latest_data.isLast,
                        (this.isLast = !0),
                        e.latest_data))
                          this.envInfo.header.custom[t] = e.latest_data[t];
                    }),
                    (e.prototype.changeReferInfo = function (e) {
                      var t = ((this.envInfo.header.referrer = e.referrer), "");
                      try {
                        t = new URL(e.referrer).host;
                      } catch (e) {}
                      this.envInfo.header.referrer_host =
                        t || this.envInfo.header.referrer_host;
                    }),
                    (e.prototype.set = function (e) {
                      var t = this;
                      Object.keys(e).forEach(function (r) {
                        var i, n, o;
                        null == e[r] && t.delete(r);
                        try {
                          t.eventCheck.calculate(r, "config");
                        } catch (e) {}
                        "traffic_type" === r &&
                          t.isLast &&
                          (t.envInfo.header.custom.$latest_traffic_source_type =
                            e[r]),
                          "evtParams" === r
                            ? (t.evtParams = d(
                                d({}, t.evtParams || {}),
                                e.evtParams || {}
                              ))
                            : "_staging_flag" === r
                            ? (t.evtParams = d(d({}, t.evtParams || {}), {
                                _staging_flag: e._staging_flag,
                              }))
                            : "reportErrorCallback" === r &&
                              "function" == typeof e[r]
                            ? (t.reportErrorCallback = e[r])
                            : ((o = n = ""),
                              -1 < r.indexOf(".") &&
                                ((n = (i = r.split("."))[0]), (o = i[1])),
                              n
                                ? "user" === n || "header" === n
                                  ? (t.envInfo[n][o] = e[r])
                                  : ((t.envInfo.header.custom[o] = e[r]),
                                    t.collect.emit(D.DEBUGGER_MESSAGE, {
                                      type: D.DEBUGGER_MESSAGE_SDK,
                                      info: "SDK \u6DFB\u52A0\u4E86Custom",
                                      level: "info",
                                      time: Date.now(),
                                      infoType: "sdk",
                                      secType: "HEADER",
                                      common: "custom",
                                    }))
                                : Object.hasOwnProperty.call(t.envInfo.user, r)
                                ? (-1 < ["user_type", "ip_addr_id"].indexOf(r)
                                    ? (t.envInfo.user[r] = e[r] && Number(e[r]))
                                    : -1 <
                                      [
                                        "user_id",
                                        "web_id",
                                        "user_unique_id",
                                        "user_unique_id_type",
                                      ].indexOf(r)
                                    ? (t.envInfo.user[r] = e[r] && String(e[r]))
                                    : -1 <
                                      ["user_is_auth", "user_is_login"].indexOf(
                                        r
                                      )
                                    ? (t.envInfo.user[r] = !!e[r])
                                    : "device_id" === r &&
                                      (t.envInfo.user[r] = e[r]),
                                  t.collect.emit(D.DEBUGGER_MESSAGE, {
                                    type: D.DEBUGGER_MESSAGE_SDK,
                                    info: "SDK \u4FEE\u6539\u4E86\u516C\u5171\u53C2\u6570",
                                    level: "info",
                                    time: Date.now(),
                                    infoType: "sdk",
                                    secType: "USER",
                                    common: r,
                                  }))
                                : Object.hasOwnProperty.call(
                                    t.envInfo.header,
                                    r
                                  )
                                ? ((t.envInfo.header[r] = e[r]),
                                  t.collect.emit(D.DEBUGGER_MESSAGE, {
                                    type: D.DEBUGGER_MESSAGE_SDK,
                                    info: "SDK \u4FEE\u6539\u4E86\u516C\u5171\u53C2\u6570",
                                    level: "info",
                                    time: Date.now(),
                                    infoType: "sdk",
                                    secType: "HEADER",
                                    common: r,
                                  }))
                                : ((t.envInfo.header.custom[r] = e[r]),
                                  t.collect.emit(D.DEBUGGER_MESSAGE, {
                                    type: D.DEBUGGER_MESSAGE_SDK,
                                    info: "SDK \u6DFB\u52A0\u4E86Custom",
                                    level: "info",
                                    time: Date.now(),
                                    infoType: "sdk",
                                    secType: "HEADER",
                                    common: "custom",
                                  })));
                      });
                    }),
                    (e.prototype.get = function (e) {
                      try {
                        return e
                          ? "evtParams" === e
                            ? this.evtParams
                            : "reportErrorCallback" === e
                            ? this[e]
                            : Object.hasOwnProperty.call(this.envInfo.user, e)
                            ? this.envInfo.user[e]
                            : Object.hasOwnProperty.call(this.envInfo.header, e)
                            ? this.envInfo.header[e]
                            : JSON.parse(JSON.stringify(this.envInfo[e]))
                          : JSON.parse(JSON.stringify(this.envInfo));
                      } catch (e) {
                        this.collect.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "\u53D1\u751F\u4E86\u5F02\u5E38",
                          level: "error",
                          time: Date.now(),
                          data: e.message,
                        });
                      }
                    }),
                    (e.prototype.setStore = function (e) {
                      try {
                        var t, r;
                        this.configPersist &&
                          (t = this.storage.getItem(this.configKey) || {}) &&
                          Object.keys(e).length &&
                          ((r = Object.assign(e, t)),
                          this.storage.setItem(this.configKey, r));
                      } catch (e) {
                        this.collect.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "\u53D1\u751F\u4E86\u5F02\u5E38",
                          level: "error",
                          time: Date.now(),
                          data: e.message,
                        });
                      }
                    }),
                    (e.prototype.getStore = function () {
                      try {
                        var e;
                        return this.configPersist &&
                          ((e = this.storage.getItem(this.configKey) || {}),
                          Object.keys(e).length)
                          ? e
                          : null;
                      } catch (e) {
                        return (
                          this.collect.emit(D.DEBUGGER_MESSAGE, {
                            type: D.DEBUGGER_MESSAGE_SDK,
                            info: "\u53D1\u751F\u4E86\u5F02\u5E38",
                            level: "error",
                            time: Date.now(),
                            data: e.message,
                          }),
                          null
                        );
                      }
                    }),
                    (e.prototype.delete = function (e) {
                      try {
                        var t;
                        this.configPersist &&
                          (t = this.storage.getItem(this.configKey) || {}) &&
                          Object.hasOwnProperty.call(t, e) &&
                          (delete t[e],
                          this.storage.setItem(this.configKey, t));
                      } catch (e) {
                        this.collect.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "\u53D1\u751F\u4E86\u5F02\u5E38",
                          level: "error",
                          time: Date.now(),
                          data: e.message,
                        });
                      }
                    }),
                    e
                  );
                })(),
                q = (() => {
                  function e(e, t) {
                    (this.isLog = t || !1), (this.name = e || "");
                  }
                  return (
                    (e.prototype.info = function (e) {
                      this.isLog;
                    }),
                    (e.prototype.warn = function (e) {
                      this.isLog;
                    }),
                    (e.prototype.error = function (e) {
                      this.isLog;
                    }),
                    (e.prototype.throw = function (e) {
                      throw (this.error(this.name), Error(e));
                    }),
                    e
                  );
                })(),
                W = (() => {
                  function e() {
                    this.spiderBot = [
                      "Baiduspider",
                      "googlebot",
                      "360Spider",
                      "haosouspider",
                      "YoudaoBot",
                      "Sogou News Spider",
                      "Yisouspider",
                      "Googlebot",
                      "Headless",
                      "Applebot",
                      "Bingbot",
                      "PetalBot",
                    ];
                  }
                  return (
                    (e.prototype.checkSpider = function (e) {
                      var t, r;
                      return (
                        !!e.enable_spider &&
                        (!(t = window.navigator.userAgent) ||
                          ((r = !1),
                          this.spiderBot.forEach(function (e) {
                            -1 !== t.indexOf(e) && (r = !0);
                          }),
                          r))
                      );
                    }),
                    e
                  );
                })(),
                V = (() => {
                  function e(e, t) {
                    (this.collect = e), (this.native = t);
                  }
                  var t = e.prototype;
                  return (
                    (t.bridgeInject = function () {
                      try {
                        return !!this.native && !!AppLogBridge;
                      } catch (e) {
                        return !1;
                      }
                    }),
                    (t.bridgeReady = function () {
                      var e = this;
                      return new Promise(function (t, r) {
                        try {
                          e.bridgeInject()
                            ? AppLogBridge.hasStarted(function (e) {
                                e ? t(!0) : r(!1);
                              })
                            : r(!1);
                        } catch (e) {
                          r(!1);
                        }
                      });
                    }),
                    (t.setNativeAppId = function (e) {
                      try {
                        AppLogBridge.setNativeAppId(JSON.stringify(e));
                      } catch (e) {}
                    }),
                    (t.setConfig = function (e) {
                      var t = this;
                      try {
                        Object.keys(e).forEach(function (r) {
                          "user_unique_id" === r
                            ? t.setUserUniqueId(e[r])
                            : e[r]
                            ? t.addHeaderInfo(r, e[r])
                            : t.removeHeaderInfo(r);
                        });
                      } catch (e) {}
                    }),
                    (t.setUserUniqueId = function (e) {
                      try {
                        AppLogBridge.setUserUniqueId(e);
                      } catch (e) {}
                    }),
                    (t.addHeaderInfo = function (e, t) {
                      try {
                        AppLogBridge.addHeaderInfo(e, t);
                      } catch (e) {}
                    }),
                    (t.setHeaderInfo = function (e) {
                      try {
                        AppLogBridge.setHeaderInfo(JSON.stringify(e));
                      } catch (e) {}
                    }),
                    (t.removeHeaderInfo = function (e) {
                      try {
                        AppLogBridge.removeHeaderInfo(e);
                      } catch (e) {}
                    }),
                    (t.reportPv = function (e) {
                      this.onEventV3("predefine_pageview", e);
                    }),
                    (t.onEventV3 = function (e, t) {
                      try {
                        AppLogBridge.onEventV3(e, t),
                          this.collect.emit(DebuggerMesssge.DEBUGGER_MESSAGE, {
                            type: DebuggerMesssge.DEBUGGER_MESSAGE_EVENT,
                            info: "bridge\u57CB\u70B9\u4E0A\u62A5",
                            time: Date.now(),
                            data: [{ events: [{ event: e, params: t }] }],
                            code: 200,
                            status: "success",
                          });
                      } catch (e) {}
                    }),
                    (t.profileSet = function (e) {
                      try {
                        AppLogBridge.profileSet(e);
                      } catch (e) {}
                    }),
                    (t.profileSetOnce = function (e) {
                      try {
                        AppLogBridge.profileSetOnce(e);
                      } catch (e) {}
                    }),
                    (t.profileIncrement = function (e) {
                      try {
                        AppLogBridge.profileIncrement(e);
                      } catch (e) {}
                    }),
                    (t.profileUnset = function (e) {
                      try {
                        AppLogBridge.profileUnset(e);
                      } catch (e) {}
                    }),
                    (t.profileAppend = function (e) {
                      try {
                        AppLogBridge.profileAppend(e);
                      } catch (e) {}
                    }),
                    e
                  );
                })(),
                J = (() => {
                  function e() {}
                  return (
                    (e.prototype.apply = function (e, t) {
                      var r = this;
                      (this.collect = e),
                        (this.storage = new B(!1, "session")),
                        (this.sessionKey = "__tea_session_id_" + t.app_id),
                        (this.expireTime = t.expireTime || 18e5),
                        (this.disableSession = t.disable_session),
                        (this.disableSessionTimeCheck =
                          t.disable_session_check),
                        this.disableSession ||
                          (this.setSessionId(),
                          this.collect.on(F.SessionReset, function (e) {
                            r.resetSessionId(e);
                          }),
                          this.collect.on(F.SessionResetTime, function () {
                            r.updateSessionIdTime();
                          }));
                    }),
                    (e.prototype.updateSessionIdTime = function () {
                      var e,
                        t = this.storage.getItem(this.sessionKey);
                      t &&
                        t.sessionId &&
                        ((e = t.timestamp),
                        Date.now() - e > this.expireTime
                          ? (t = { sessionId: w(), timestamp: Date.now() })
                          : (t.timestamp = Date.now()),
                        this.storage.setItem(this.sessionKey, t),
                        this.resetExpTime());
                    }),
                    (e.prototype.setSessionId = function () {
                      var e = this,
                        t = this.storage.getItem(this.sessionKey);
                      t && t.sessionId
                        ? (t.timestamp = Date.now())
                        : (t = { sessionId: w(), timestamp: Date.now() }),
                        this.storage.setItem(this.sessionKey, t),
                        this.disableSessionTimeCheck ||
                          (this.sessionExp = setInterval(function () {
                            e.checkEXp();
                          }, this.expireTime));
                    }),
                    (e.prototype.getSessionId = function () {
                      var e = this.storage.getItem(this.sessionKey);
                      return !this.disableSession && e && e.sessionId
                        ? e.sessionId
                        : "";
                    }),
                    (e.prototype.resetExpTime = function () {
                      var e = this;
                      this.sessionExp &&
                        (clearInterval(this.sessionExp),
                        (this.sessionExp = setInterval(function () {
                          e.checkEXp();
                        }, this.expireTime)));
                    }),
                    (e.prototype.resetSessionId = function (e) {
                      (e = { sessionId: e || w(), timestamp: Date.now() }),
                        this.storage.setItem(this.sessionKey, e);
                    }),
                    (e.prototype.checkEXp = function () {
                      var e = this.storage.getItem(this.sessionKey);
                      e &&
                        e.sessionId &&
                        Date.now() - e.timestamp + 30 >= this.expireTime &&
                        ((e = { sessionId: w(), timestamp: Date.now() }),
                        this.storage.setItem(this.sessionKey, e));
                    }),
                    e
                  );
                })(),
                Z = (() => {
                  function e() {
                    (this.eventLimit = 50),
                      (this.enable_ttwebid = !1),
                      (this.eventCache = []),
                      (this.beconEventCache = []);
                  }
                  return (
                    (e.prototype.apply = function (e, t) {
                      var r = this,
                        i =
                          ((this.collect = e),
                          (this.config = t),
                          (this.configManager = e.configManager),
                          (this.eventCheck = new G(e, t)),
                          (this.cacheStorgae = new B(!0)),
                          (this.localStorage = new B(!1)),
                          (this.maxReport = t.max_report || 10),
                          (this.reportTime =
                            t.reportTime || t.report_time || 30),
                          (this.timeout = t.timeout || 1e5),
                          (this.enable_ttwebid = t.enable_ttwebid),
                          (this.reportUrl =
                            t.report_url || this.configManager.getUrl("event")),
                          (this.eventKey =
                            "__tea_cache_events_" +
                            this.configManager.get("app_id")),
                          (this.beconKey =
                            "__tea_cache_events_becon_" +
                            this.configManager.get("app_id")),
                          (this.abKey =
                            "__tea_sdk_ab_version_" +
                            this.configManager.get("app_id")),
                          (this.refer_key =
                            "__tea_cache_refer_" +
                            this.configManager.get("app_id")),
                          (this.pageId = w()),
                          this.collect.on(F.Ready, function () {
                            r.reportAll(!1);
                          }),
                          this.collect.on(F.ConfigDomain, function () {
                            r.reportUrl = r.configManager.getUrl("event");
                          }),
                          this.collect.on(F.Event, function (e) {
                            r.event(e);
                          }),
                          this.collect.on(F.BeconEvent, function (e) {
                            r.beconEvent(e);
                          }),
                          this.collect.on(F.CleanEvents, function () {
                            r.reportAll(!1);
                          }),
                          this.linster());
                      this.collect.on(F.DestoryInstance, function () {
                        i && i();
                      });
                    }),
                    (e.prototype.linster = function () {
                      function e() {
                        r.reportAll(!0);
                      }
                      function t() {
                        "hidden" === document.visibilityState &&
                          r.reportAll(!0);
                      }
                      var r = this;
                      return (
                        window.addEventListener("unload", e, !1),
                        y()
                          ? window.addEventListener("pagehide", e, !1)
                          : window.addEventListener("beforeunload", e, !1),
                        document.addEventListener("visibilitychange", t, !1),
                        function () {
                          window.removeEventListener("unload", e),
                            window.removeEventListener("pagehide", e, !1),
                            window.removeEventListener("beforeunload", e, !1),
                            document.removeEventListener(
                              "visibilitychange",
                              t,
                              !1
                            );
                        }
                      );
                    }),
                    (e.prototype.reportAll = function (e) {
                      this.report(e), this.reportBecon();
                    }),
                    (e.prototype.event = function (e) {
                      var t,
                        r,
                        i,
                        n,
                        o = this;
                      try {
                        this.collect.destroy ||
                          this.collect.sdkStop ||
                          (this.config.enable_ios_sendbeacon && y()
                            ? this.beconEvent(e)
                            : ((t =
                                this.cacheStorgae.getItem(this.eventKey) || []),
                              (r = e),
                              (i = p(
                                (r = this.config.batch_event
                                  ? this.batchEvent(e)
                                  : r),
                                t
                              )),
                              this.cacheStorgae.setItem(this.eventKey, i),
                              this.reportTimeout &&
                                clearTimeout(this.reportTimeout),
                              i.length >= this.maxReport
                                ? this.report(!1)
                                : ((n = this.reportTime),
                                  (this.reportTimeout = setTimeout(function () {
                                    o.report(!1), (o.reportTimeout = null);
                                  }, n)))));
                      } catch (e) {
                        this.collect.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "SDK \u53D1\u751F\u4E86\u5F02\u5E38",
                          level: "error",
                          time: Date.now(),
                          data: e.message,
                          infoType: "sdk",
                        });
                      }
                    }),
                    (e.prototype.beconEvent = function (e) {
                      this.collect.destroy ||
                        this.collect.sdkStop ||
                        ((e = p(
                          e,
                          this.cacheStorgae.getItem(this.beconKey) || []
                        )),
                        this.cacheStorgae.setItem(this.beconKey, e),
                        this.collect.tokenManager.getReady() &&
                          this.collect.sdkReady &&
                          (this.cacheStorgae.removeItem(this.beconKey),
                          this.send(this.split(this.merge(e)), !0)));
                    }),
                    (e.prototype.reportBecon = function () {
                      var e;
                      !this.collect.destroy &&
                        !this.collect.sdkStop &&
                        this.collect.tokenManager.getReady() &&
                        this.collect.sdkReady &&
                        (e = this.cacheStorgae.getItem(this.beconKey) || []) &&
                        e.length &&
                        (this.cacheStorgae.removeItem(this.beconKey),
                        this.send(this.split(this.merge(e)), !0));
                    }),
                    (e.prototype.report = function (e) {
                      var t;
                      !this.collect.destroy &&
                        !this.collect.sdkStop &&
                        this.collect.tokenManager.getReady() &&
                        this.collect.sdkReady &&
                        (t = this.cacheStorgae.getItem(this.eventKey) || [])
                          .length &&
                        (this.cacheStorgae.removeItem(this.eventKey),
                        this.config.batch_event
                          ? this.send([t], e)
                          : this.sliceEvent(t, e));
                    }),
                    (e.prototype.batchEvent = function (e) {
                      var t = [];
                      if (e.length > this.eventLimit)
                        for (var r = 0; r < e.length; r += this.eventLimit) {
                          var i = e.slice(r, r + this.eventLimit),
                            n = this.merge(i);
                          t.push(n);
                        }
                      else t = n = this.merge(e);
                      return t;
                    }),
                    (e.prototype.sliceEvent = function (e, t) {
                      if (e.length > this.eventLimit)
                        for (var r = 0; r < e.length; r += this.eventLimit) {
                          var i = e.slice(r, r + this.eventLimit),
                            n = this.split(this.merge(i));
                          this.send(n, t);
                        }
                      else (n = this.split(this.merge(e))), this.send(n, t);
                    }),
                    (e.prototype.handleRefer = function () {
                      var e,
                        t = "";
                      try {
                        t =
                          (this.config.spa || this.config.autotrack) &&
                          (e = this.localStorage.getItem(this.refer_key) || {})
                            .routeChange
                            ? e.refer_key
                            : this.configManager.get("referrer");
                      } catch (e) {
                        t = document.referrer;
                      }
                      return t;
                    }),
                    (e.prototype.merge = function (e, t) {
                      var r = this,
                        i = this.configManager.get(),
                        n = i.header,
                        o = i.user,
                        s =
                          (this.config.enable_pageid &&
                            (n.custom.page_id = this.pageId),
                          (n.custom = JSON.stringify(n.custom)),
                          this.configManager.get("evtParams")),
                        a = this.configManager.get("user_unique_id_type"),
                        i = [];
                      try {
                        var c = e.filter(function (e) {
                            try {
                              Object.keys(s).length &&
                                !t &&
                                (e.params = d(d({}, s), e.params)),
                                a && (e.params.$user_unique_id_type = a);
                              var i = r.configManager.getAbCache(),
                                n =
                                  o[r.config.ab_user_mode] || o.user_unique_id;
                              return (
                                i &&
                                  i.uuid &&
                                  i.uuid === n &&
                                  r.configManager.getAbVersion() &&
                                  (e.ab_sdk_version =
                                    r.configManager.getAbVersion()),
                                (e.session_id =
                                  r.collect.sessionManager.getSessionId()),
                                (e.params = JSON.stringify(e.params)),
                                e
                              );
                            } catch (e) {
                              return (
                                r.collect.emit(D.DEBUGGER_MESSAGE, {
                                  type: D.DEBUGGER_MESSAGE_SDK,
                                  info: "SDK \u5904\u7406Event\u6570\u636E\u5F02\u5E38",
                                  level: "error",
                                  time: Date.now(),
                                  data: e.message,
                                  infoType: "sdk",
                                }),
                                !1
                              );
                            }
                          }),
                          u = JSON.parse(
                            JSON.stringify({ events: c, user: o, header: n })
                          );
                        (u.local_time = Math.floor(Date.now() / 1e3)),
                          (u.user_unique_type = this.config.enable_ttwebid
                            ? this.config.user_unique_type
                            : void 0),
                          (u.verbose = 1),
                          i.push(u);
                      } catch (e) {}
                      return i;
                    }),
                    (e.prototype.split = function (e) {
                      return e.map(function (e) {
                        var t = [];
                        return t.push(e), t;
                      });
                    }),
                    (e.prototype.blockEvent = function (e) {
                      try {
                        var t,
                          r,
                          i = this.blockList;
                        return (
                          this.config.enable_logsetting &&
                            ((t = this.blockList),
                            (r =
                              this.logSetting.getSettingData(
                                "blocklist_events"
                              ).block_event),
                            (i = t.concat(
                              r.filter(function (e) {
                                return -1 === t.indexOf(e);
                              })
                            ))),
                          !(i && i.length && i.includes(e))
                        );
                      } catch (e) {
                        return !0;
                      }
                    }),
                    (e.prototype.whiteEvent = function (e) {
                      var t;
                      try {
                        return (
                          null == (t = this.whiteList) ||
                          !t.length ||
                          !!this.whiteList.includes(e)
                        );
                      } catch (e) {
                        return !0;
                      }
                    }),
                    (e.prototype.customAllowFilter = function (e, t) {
                      try {
                        if (
                          t ||
                          !this.config.enable_logsetting ||
                          !this.config.enable_logsetting_header_custom
                        )
                          return JSON.stringify(e);
                        var r =
                            this.logSetting.getSettingData()
                              .header_custom_allow,
                          i = {};
                        if (r && r.length && Object.keys(e).length) {
                          var n,
                            o = new Set(r);
                          for (n in e) o.has(n) && (i[n] = e[n]);
                        }
                        return JSON.stringify(i);
                      } catch (t) {
                        return (
                          this.collect.emit(D.DEBUGGER_MESSAGE, {
                            type: D.DEBUGGER_MESSAGE_SDK,
                            info: "SDK \u6267\u884CcustomAllowFilter\u53D1\u751F\u4E86\u5F02\u5E38",
                            level: "error",
                            time: Date.now(),
                            data: t.message,
                            infoType: "sdk",
                          }),
                          JSON.stringify(e)
                        );
                      }
                    }),
                    (e.prototype.paramsAllowFilter = function (e, t) {
                      try {
                        if (
                          !t &&
                          this.config.enable_logsetting &&
                          this.config.enable_logsetting_params
                        ) {
                          var r = this.logSetting.getSettingData().params_block,
                            i = e.event,
                            n = e.params,
                            o = {};
                          if (r && r[i] && r[i].length) {
                            var s,
                              a = new Set(r[i]);
                            for (s in n)
                              (!this.logSetting
                                .getPredefineParamsList()
                                .has(s) &&
                                a.has(s)) ||
                                (o[s] = n[s]);
                            return JSON.stringify(o);
                          }
                        }
                        return JSON.stringify(e.params);
                      } catch (t) {
                        return (
                          this.collect.emit(D.DEBUGGER_MESSAGE, {
                            type: D.DEBUGGER_MESSAGE_SDK,
                            info: "SDK \u6267\u884CparamsAllowFilter\u53D1\u751F\u4E86\u5F02\u5E38",
                            level: "error",
                            time: Date.now(),
                            data: t.message,
                            infoType: "sdk",
                          }),
                          JSON.stringify(e.params)
                        );
                      }
                    }),
                    (e.prototype.send = function (e, t) {
                      var r = this;
                      e.length &&
                        !this.config.disable_track_event &&
                        e.forEach(function (e) {
                          try {
                            var i,
                              n = JSON.parse(JSON.stringify(e)),
                              o =
                                (r.config.filter && (n = r.config.filter(n)),
                                r.collect.eventFilter &&
                                  n &&
                                  (n = r.collect.eventFilter(n)),
                                n || e),
                              s = JSON.parse(JSON.stringify(o));
                            r.eventCheck.checkVerify(s),
                              o.length &&
                                ((i = !0),
                                o.forEach(function (e) {
                                  e.events.length || (i = !1);
                                }),
                                i &&
                                  (r.collect.emit(F.SubmitBefore, o),
                                  r.collect.requestManager.useRequest({
                                    url: r.reportUrl,
                                    data: o,
                                    success: function (e, t) {
                                      e && 0 !== e.e
                                        ? (r.collect.emit(F.SubmitError, {
                                            type: "f_data",
                                            eventData: t,
                                            errorCode: e.e,
                                            response: e,
                                          }),
                                          r.collect.emit(D.DEBUGGER_MESSAGE, {
                                            type: D.DEBUGGER_MESSAGE_EVENT,
                                            info: "\u57CB\u70B9\u4E0A\u62A5\u5931\u8D25",
                                            time: Date.now(),
                                            data: s,
                                            code: e.e,
                                            msg: e.m || "",
                                            failType:
                                              "\u6570\u636E\u5F02\u5E38\u5931\u8D25",
                                            status: "fail",
                                          }))
                                        : (r.collect.emit(F.SubmitScuess, {
                                            eventData: t,
                                            res: e,
                                          }),
                                          r.collect.emit(D.DEBUGGER_MESSAGE, {
                                            type: D.DEBUGGER_MESSAGE_EVENT,
                                            info: "\u57CB\u70B9\u4E0A\u62A5\u6210\u529F",
                                            time: Date.now(),
                                            data: s,
                                            code: 200,
                                            status: "success",
                                          }));
                                    },
                                    fail: function (e, t) {
                                      r.configManager.get(
                                        "reportErrorCallback"
                                      )(e, t),
                                        r.collect.emit(F.SubmitError, {
                                          type: "f_net",
                                          eventData: e,
                                          errorCode: t,
                                        }),
                                        r.collect.emit(D.DEBUGGER_MESSAGE, {
                                          type: D.DEBUGGER_MESSAGE_EVENT,
                                          info: "\u57CB\u70B9\u4E0A\u62A5\u7F51\u7EDC\u5F02\u5E38",
                                          time: Date.now(),
                                          data: s,
                                          code: t,
                                          failType:
                                            "\u7F51\u7EDC\u5F02\u5E38\u5931\u8D25",
                                          status: "fail",
                                        });
                                    },
                                    timeout: r.timeout,
                                    useBeacon: t,
                                    withCredentials: r.enable_ttwebid,
                                    zip: !0,
                                  }),
                                  r.collect.emit(F.SubmitAfter, o)));
                          } catch (e) {
                            r.collect.emit(D.DEBUGGER_MESSAGE, {
                              type: D.DEBUGGER_MESSAGE_SDK,
                              info: "SDK\u53D1\u9001\u57CB\u70B9\u53D1\u751F\u4E86\u5F02\u5E38",
                              level: "error",
                              time: Date.now(),
                              data: e.message,
                              infoType: "sdk",
                            });
                          }
                        });
                    }),
                    e
                  );
                })(),
                X = (() => {
                  function e() {
                    (this.cacheToken = {}),
                      (this.enableCookie = !1),
                      (this.enable_ttwebid = !1),
                      (this.enableCustomWebid = !1);
                  }
                  return (
                    (e.prototype.apply = function (e, t) {
                      var r = this;
                      (this.collect = e),
                        (this.config = t),
                        (this.configManager = this.collect.configManager),
                        (this.storage = new B(!1)),
                        (this.tokenKey = "__tea_cache_tokens_" + t.app_id),
                        (this.enable_ttwebid = t.enable_ttwebid),
                        (this.enableCustomWebid = t.enable_custom_webid),
                        this.collect.on(F.ConfigUuid, function (e) {
                          r.setUuid(e);
                        }),
                        this.collect.on(F.ConfigWebId, function (e) {
                          r.setWebId(e);
                        }),
                        this.collect.on(F.ConfigDiD, function (e) {
                          r.setDeviceId(e);
                        }),
                        (this.enableCookie = t.cross_subdomain),
                        (this.expiresTime = t.cookie_expire || 6048e5),
                        (this.cookieDomain = t.cookie_domain || ""),
                        this.checkStorage();
                    }),
                    (e.prototype.checkStorage = function () {
                      var e,
                        t = this;
                      this.enableCookie
                        ? ((e = this.storage.getCookie(
                            this.tokenKey,
                            this.cookieDomain
                          )),
                          (this.cacheToken =
                            e && "string" == typeof e ? JSON.parse(e) : {}))
                        : (this.cacheToken =
                            this.storage.getItem(this.tokenKey) || {}),
                        (this.tokenType =
                          this.cacheToken && this.cacheToken._type_
                            ? this.cacheToken._type_
                            : "default"),
                        "custom" !== this.tokenType || this.enableCustomWebid
                          ? this.enableCustomWebid
                            ? this.collect.on(F.CustomWebId, function () {
                                (t.tokenReady = !0),
                                  t.collect.emit(F.TokenComplete);
                              })
                            : this.checkEnv() ||
                              (this.enable_ttwebid
                                ? this.completeTtWid(this.cacheToken)
                                : this.check())
                          : this.remoteWebid();
                    }),
                    (e.prototype.check = function () {
                      this.cacheToken && this.cacheToken.web_id
                        ? this.complete(this.cacheToken)
                        : this.config.disable_webid
                        ? this.complete({
                            web_id: k(),
                            user_unique_id:
                              this.configManager.get("user_unique_id") || k(),
                          })
                        : this.remoteWebid();
                    }),
                    (e.prototype.checkEnv = function () {
                      var e = window.navigator.userAgent;
                      return (
                        (-1 !== e.indexOf("miniProgram") ||
                          -1 !== e.indexOf("MiniProgram")) &&
                        !(
                          !(e = b(window.location.href)) ||
                          !e.Web_ID ||
                          (this.complete({
                            web_id: "" + e.Web_ID,
                            user_unique_id:
                              this.configManager.get("user_unique_id") ||
                              "" + e.Web_ID,
                          }),
                          0)
                        )
                      );
                    }),
                    (e.prototype.remoteWebid = function () {
                      var e = this,
                        t = this.configManager.getUrl("webid"),
                        r = {
                          app_key: this.config.app_key,
                          app_id: this.config.app_id,
                          url: location.href,
                          user_agent: window.navigator.userAgent,
                          referer: document.referrer,
                          user_unique_id: "",
                        };
                      this.collect.emit(D.DEBUGGER_MESSAGE, {
                        type: D.DEBUGGER_MESSAGE_SDK,
                        info: "SDK \u53D1\u8D77WebID\u8BF7\u6C42",
                        logType: "fetch",
                        level: "info",
                        time: Date.now(),
                        data: r,
                        infoType: "sdk",
                      }),
                        this.collect.requestManager.useRequest({
                          url: t,
                          data: r,
                          success: function (t) {
                            var r, i;
                            t && 0 === t.e
                              ? ((i = t.web_id),
                                e.collect.emit(D.DEBUGGER_MESSAGE, {
                                  type: D.DEBUGGER_MESSAGE_SDK,
                                  info: "WebID\u8BF7\u6C42\u6210\u529F",
                                  logType: "fetch",
                                  level: "info",
                                  time: Date.now(),
                                  data: t,
                                  infoType: "sdk",
                                }))
                              : ((r = k()),
                                e.collect.configManager.set({
                                  localWebId: (i = r),
                                }),
                                e.collect.emit(F.TokenError),
                                e.collect.emit(D.DEBUGGER_MESSAGE, {
                                  type: D.DEBUGGER_MESSAGE_SDK,
                                  info: "WebID\u8BF7\u6C42\u8FD4\u56DE\u503C\u5F02\u5E38\uFF0C\u91C7\u7528\u672C\u5730\u751F\u6210",
                                  logType: "fetch",
                                  level: "warn",
                                  time: Date.now(),
                                  data: t,
                                  infoType: "sdk",
                                }),
                                e.collect.logger.warn(
                                  "appid: " +
                                    e.config.app_id +
                                    " get webid error, use local webid~"
                                )),
                              e.complete({
                                web_id: e.configManager.get("web_id") || i,
                                user_unique_id:
                                  e.configManager.get("user_unique_id") || i,
                              });
                          },
                          fail: function () {
                            var t = k();
                            e.complete({
                              web_id: e.configManager.get("web_id") || t,
                              user_unique_id:
                                e.configManager.get("user_unique_id") || t,
                            }),
                              e.collect.configManager.set({ localWebId: t }),
                              e.collect.emit(F.TokenError),
                              e.collect.emit(D.DEBUGGER_MESSAGE, {
                                type: D.DEBUGGER_MESSAGE_SDK,
                                info: "WebID\u8BF7\u6C42\u7F51\u7EDC\u5F02\u5E38\uFF0C\u91C7\u7528\u672C\u5730\u751F\u6210",
                                logType: "fetch",
                                level: "error",
                                time: Date.now(),
                                data: { localWebId: t },
                                infoType: "sdk",
                              }),
                              e.collect.logger.warn(
                                "appid: " +
                                  e.config.app_id +
                                  ", get webid error, use local webid~"
                              );
                          },
                          timeout: 3e5,
                        });
                    }),
                    (e.prototype.complete = function (e) {
                      var t = e.web_id,
                        r = e.user_unique_id,
                        i = e.device_id;
                      (e.timestamp = Date.now()),
                        this.collect.configManager.set({
                          web_id: t,
                          user_unique_id: r,
                        }),
                        this.config.enable_device_id
                          ? ((i =
                              this.configManager.get("device_id") || i || t),
                            this.collect.configManager.set({ device_id: i }),
                            (e = d(d({}, e), { device_id: i })))
                          : null != e && e.device_id && delete e.device_id,
                        this.setStorage(e),
                        (this.tokenReady = !0),
                        this.collect.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "SDK \u5B8C\u6210\u7528\u6237\u4FE1\u606F\u8BBE\u7F6E",
                          logType: "info",
                          level: "info",
                          time: Date.now(),
                          data: { web_id: t, user_unique_id: r },
                          infoType: "sdk",
                        }),
                        this.collect.emit(F.TokenComplete);
                    }),
                    (e.prototype.completeTtWid = function (e) {
                      var t = e.user_unique_id || "",
                        r = this.configManager.get("user_unique_id");
                      (r || t) &&
                        this.configManager.set({ user_unique_id: r || t }),
                        this.setStorage(e),
                        (this.tokenReady = !0),
                        this.collect.emit(F.TokenComplete);
                    }),
                    (e.prototype.setUuid = function (e) {
                      var t, r;
                      e &&
                      -1 === ["null", "undefined", "Null", "None"].indexOf(e)
                        ? ((e = String(e)),
                          (t = this.configManager.get("user_unique_id")),
                          (r =
                            this.cacheToken && this.cacheToken.user_unique_id),
                          (e === t && e === r) ||
                            (this.configManager.set({ user_unique_id: e }),
                            this.cacheToken || (this.cacheToken = {}),
                            (this.cacheToken.user_unique_id = e),
                            (this.cacheToken.timestamp = Date.now()),
                            this.setStorage(this.cacheToken),
                            this.collect.emit(F.TokenChange, "uuid"),
                            this.collect.emit(F.SessionReset)))
                        : this.clearUuid();
                    }),
                    (e.prototype.clearUuid = function () {
                      this.config.enable_ttwebid ||
                        (this.configManager.get("web_id") &&
                          this.configManager.get("user_unique_id") !==
                            this.configManager.get("web_id") &&
                          (this.configManager.set({
                            user_unique_id: this.configManager.get("web_id"),
                          }),
                          this.cacheToken &&
                            this.cacheToken.web_id &&
                            ((this.cacheToken.user_unique_id =
                              this.cacheToken.web_id),
                            (this.cacheToken.timestamp = Date.now()),
                            this.setStorage(this.cacheToken)),
                          this.collect.emit(F.TokenReset, "uuid")));
                    }),
                    (e.prototype.setWebId = function (e) {
                      var t, r;
                      e &&
                        !this.config.enable_ttwebid &&
                        (this.cacheToken && this.cacheToken.web_id
                          ? this.cacheToken.web_id !== e &&
                            ((this.cacheToken.user_unique_id =
                              this.cacheToken.web_id ===
                              this.cacheToken.user_unique_id
                                ? e
                                : this.cacheToken.user_unique_id),
                            (this.cacheToken.web_id = e))
                          : ((this.cacheToken = {}),
                            (this.cacheToken.web_id = e),
                            (this.cacheToken.user_unique_id = e)),
                        (this.cacheToken.timestamp = Date.now()),
                        (t = this.configManager.get("web_id")),
                        ((r = this.configManager.get("user_unique_id")) &&
                          r !== t) ||
                          (this.configManager.set({ user_unique_id: e }),
                          this.collect.emit(F.TokenChange, "uuid")),
                        t !== e &&
                          (this.configManager.set({ web_id: e }),
                          this.collect.emit(F.TokenChange, "webid")),
                        this.setStorage(this.cacheToken));
                    }),
                    (e.prototype.setDeviceId = function (e) {
                      this.configManager.set({ device_id: e }),
                        this.config.enable_device_id &&
                          this.cacheToken &&
                          ((this.cacheToken.device_id = e),
                          (this.cacheToken.timestamp = Date.now()),
                          this.setStorage(this.cacheToken));
                    }),
                    (e.prototype.setStorage = function (e) {
                      (e._type_ = this.enableCustomWebid
                        ? "custom"
                        : "default"),
                        delete e["diss".split("").reverse().join("")],
                        this.enableCookie || this.enable_ttwebid
                          ? (this.storage.setCookie(
                              this.tokenKey,
                              e,
                              this.expiresTime,
                              this.cookieDomain
                            ),
                            this.enable_ttwebid &&
                              (delete e.web_id,
                              this.storage.setItem(this.tokenKey, e)))
                          : this.storage.setItem(this.tokenKey, e),
                        (this.cacheToken = e);
                    }),
                    (e.prototype.getReady = function () {
                      return this.tokenReady;
                    }),
                    (e.prototype.getTobId = function () {
                      var e = this;
                      return new Promise(function (t) {
                        var r = {
                          app_id: e.config.app_id,
                          user_unique_id: e.configManager.get("user_unique_id"),
                          web_id: e.configManager.get("web_id"),
                          user_unique_id_type: e.configManager.get(
                            "user_unique_id_type"
                          ),
                        };
                        e.collect.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "SDK \u53D1\u8D77GetToken\u8BF7\u6C42",
                          logType: "fetch",
                          level: "info",
                          time: Date.now(),
                          data: r,
                          infoType: "sdk",
                        }),
                          e.collect.requestManager.useRequest({
                            url: e.configManager.getUrl("tobid"),
                            data: r,
                            success: function (r) {
                              r && 0 === r.e
                                ? (t(r.tobid),
                                  e.collect.emit(D.DEBUGGER_MESSAGE, {
                                    type: D.DEBUGGER_MESSAGE_SDK,
                                    info: "GetToken\u8BF7\u6C42\u6210\u529F",
                                    logType: "fetch",
                                    level: "info",
                                    time: Date.now(),
                                    data: r,
                                    infoType: "sdk",
                                  }))
                                : (t(""),
                                  e.collect.emit(D.DEBUGGER_MESSAGE, {
                                    type: D.DEBUGGER_MESSAGE_SDK,
                                    info: "GetToken\u8BF7\u6C42\u5931\u8D25",
                                    logType: "fetch",
                                    level: "error",
                                    time: Date.now(),
                                    data: r,
                                    infoType: "sdk",
                                  }));
                            },
                            fail: function () {
                              t(""),
                                e.collect.emit(D.DEBUGGER_MESSAGE, {
                                  type: D.DEBUGGER_MESSAGE_SDK,
                                  info: "GetToken\u8BF7\u6C42\u5931\u8D25",
                                  logType: "fetch",
                                  level: "error",
                                  time: Date.now(),
                                  infoType: "sdk",
                                });
                            },
                            time: 3e4,
                            withCredentials: e.enable_ttwebid,
                          });
                      });
                    }),
                    e
                  );
                })();
              function Q(e) {
                for (var t = e.length; 0 <= --t; ) e[t] = 0;
              }
              var $ = new Uint8Array([
                  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4,
                  4, 4, 4, 5, 5, 5, 5, 0,
                ]),
                Y = new Uint8Array([
                  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9,
                  9, 10, 10, 11, 11, 12, 12, 13, 13,
                ]),
                ee = new Uint8Array([
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7,
                ]),
                et = new Uint8Array([
                  16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1,
                  15,
                ]),
                er = Array(576),
                ei = (Q(er), Array(60)),
                en = (Q(ei), Array(512)),
                eo = (Q(en), Array(256)),
                es = (Q(eo), Array(29));
              Q(es);
              var ea,
                ec,
                eu,
                el = Array(30);
              function ef(e, t, r, i, n) {
                (this.static_tree = e),
                  (this.extra_bits = t),
                  (this.extra_base = r),
                  (this.elems = i),
                  (this.max_length = n),
                  (this.has_stree = e && e.length);
              }
              function eh(e, t) {
                (this.dyn_tree = e), (this.max_code = 0), (this.stat_desc = t);
              }
              function ed(e) {
                return e < 256 ? en[e] : en[256 + (e >>> 7)];
              }
              function ep(e, t, r) {
                eP(e, r[2 * t], r[2 * t + 1]);
              }
              function eg(e, t) {
                for (var r = 0; (r |= 1 & e), (e >>>= 1), (r <<= 1), 0 < --t; );
                return r >>> 1;
              }
              function em(e, t, r) {
                for (var i, n = Array(16), o = 0, s = 1; s <= 15; s++)
                  (o = (o + r[s - 1]) << 1), (n[s] = o);
                for (i = 0; i <= t; i++) {
                  var a = e[2 * i + 1];
                  0 !== a && (e[2 * i] = eg(n[a]++, a));
                }
              }
              function ey(e) {
                for (var t = 0; t < 286; t++) e.dyn_ltree[2 * t] = 0;
                for (t = 0; t < 30; t++) e.dyn_dtree[2 * t] = 0;
                for (t = 0; t < 19; t++) e.bl_tree[2 * t] = 0;
                (e.dyn_ltree[512] = 1),
                  (e.opt_len = e.static_len = 0),
                  (e.sym_next = e.matches = 0);
              }
              function e_(e) {
                8 < e.bi_valid
                  ? eR(e, e.bi_buf)
                  : 0 < e.bi_valid && (e.pending_buf[e.pending++] = e.bi_buf),
                  (e.bi_buf = 0),
                  (e.bi_valid = 0);
              }
              function eb(e, t, r) {
                for (
                  var i = e.heap[r], n = r << 1;
                  n <= e.heap_len &&
                  (n < e.heap_len &&
                    eU(t, e.heap[n + 1], e.heap[n], e.depth) &&
                    n++,
                  !eU(t, i, e.heap[n], e.depth));

                )
                  (e.heap[r] = e.heap[n]), (r = n), (n <<= 1);
                e.heap[r] = i;
              }
              function ev(e, t, r) {
                var i,
                  n,
                  o,
                  s,
                  a = 0;
                if (0 !== e.sym_next)
                  for (
                    ;
                    (i =
                      (255 & e.pending_buf[e.sym_buf + a++]) +
                      ((255 & e.pending_buf[e.sym_buf + a++]) << 8)),
                      (n = e.pending_buf[e.sym_buf + a++]),
                      0 == i
                        ? ep(e, n, t)
                        : (ep(e, (o = eo[n]) + 256 + 1, t),
                          0 !== (s = $[o]) && eP(e, (n -= es[o]), s),
                          ep(e, (o = ed(--i)), r),
                          0 !== (s = Y[o]) && eP(e, (i -= el[o]), s)),
                      a < e.sym_next;

                  );
                ep(e, 256, t);
              }
              function ez(e, t) {
                var r,
                  i,
                  n,
                  o = t.dyn_tree,
                  s = t.stat_desc.static_tree,
                  a = t.stat_desc.has_stree,
                  c = t.stat_desc.elems,
                  u = -1;
                for (e.heap_len = 0, e.heap_max = 573, r = 0; r < c; r++)
                  0 !== o[2 * r]
                    ? ((e.heap[++e.heap_len] = u = r), (e.depth[r] = 0))
                    : (o[2 * r + 1] = 0);
                for (; e.heap_len < 2; )
                  (o[2 * (n = e.heap[++e.heap_len] = u < 2 ? ++u : 0)] = 1),
                    (e.depth[n] = 0),
                    e.opt_len--,
                    a && (e.static_len -= s[2 * n + 1]);
                for (t.max_code = u, r = e.heap_len >> 1; 1 <= r; r--)
                  eb(e, o, r);
                for (
                  n = c;
                  (r = e.heap[1]),
                    (e.heap[1] = e.heap[e.heap_len--]),
                    eb(e, o, 1),
                    (i = e.heap[1]),
                    (e.heap[--e.heap_max] = r),
                    (e.heap[--e.heap_max] = i),
                    (o[2 * n] = o[2 * r] + o[2 * i]),
                    (e.depth[n] =
                      (e.depth[r] >= e.depth[i] ? e.depth[r] : e.depth[i]) + 1),
                    (o[2 * r + 1] = o[2 * i + 1] = n),
                    (e.heap[1] = n++),
                    eb(e, o, 1),
                    2 <= e.heap_len;

                );
                (e.heap[--e.heap_max] = e.heap[1]),
                  ((e) => {
                    for (
                      var r,
                        i,
                        n,
                        o,
                        s,
                        a = t.dyn_tree,
                        c = t.max_code,
                        u = t.stat_desc.static_tree,
                        l = t.stat_desc.has_stree,
                        f = t.stat_desc.extra_bits,
                        h = t.stat_desc.extra_base,
                        d = t.stat_desc.max_length,
                        p = 0,
                        g = 0;
                      g <= 15;
                      g++
                    )
                      e.bl_count[g] = 0;
                    for (
                      a[2 * e.heap[e.heap_max] + 1] = 0, r = e.heap_max + 1;
                      r < 573;
                      r++
                    )
                      (g = a[2 * a[2 * (i = e.heap[r]) + 1] + 1] + 1) > d &&
                        ((g = d), p++),
                        (a[2 * i + 1] = g),
                        c < i ||
                          (e.bl_count[g]++,
                          (o = 0),
                          h <= i && (o = f[i - h]),
                          (s = a[2 * i]),
                          (e.opt_len += s * (g + o)),
                          l && (e.static_len += s * (u[2 * i + 1] + o)));
                    if (0 !== p) {
                      do for (g = d - 1; 0 === e.bl_count[g]; ) g--;
                      while (
                        (e.bl_count[g]--,
                        (e.bl_count[g + 1] += 2),
                        e.bl_count[d]--,
                        0 < (p -= 2))
                      );
                      for (g = d; 0 !== g; g--)
                        for (i = e.bl_count[g]; 0 !== i; )
                          (n = e.heap[--r]) > c ||
                            (a[2 * n + 1] !== g &&
                              ((e.opt_len += (g - a[2 * n + 1]) * a[2 * n]),
                              (a[2 * n + 1] = g)),
                            i--);
                    }
                  })(e),
                  em(o, u, e.bl_count);
              }
              function eS(e, t, r) {
                var i,
                  n,
                  o = -1,
                  s = t[1],
                  a = 0,
                  c = 7,
                  u = 4;
                for (
                  0 === s && ((c = 138), (u = 3)),
                    t[2 * (r + 1) + 1] = 65535,
                    i = 0;
                  i <= r;
                  i++
                )
                  (n = s),
                    (s = t[2 * (i + 1) + 1]),
                    (++a < c && n === s) ||
                      (a < u
                        ? (e.bl_tree[2 * n] += a)
                        : 0 !== n
                        ? (n !== o && e.bl_tree[2 * n]++, e.bl_tree[32]++)
                        : a <= 10
                        ? e.bl_tree[34]++
                        : e.bl_tree[36]++,
                      (o = n),
                      (u =
                        (a = 0) === s
                          ? ((c = 138), 3)
                          : n === s
                          ? ((c = 6), 3)
                          : ((c = 7), 4)));
              }
              function ew(e, t, r) {
                var i,
                  n,
                  o = -1,
                  s = t[1],
                  a = 0,
                  c = 7,
                  u = 4;
                for (0 === s && ((c = 138), (u = 3)), i = 0; i <= r; i++)
                  if (
                    ((n = s), (s = t[2 * (i + 1) + 1]), !(++a < c && n === s))
                  ) {
                    if (a < u) for (; ep(e, n, e.bl_tree), 0 != --a; );
                    else
                      0 !== n
                        ? (n !== o && (ep(e, n, e.bl_tree), a--),
                          ep(e, 16, e.bl_tree),
                          eP(e, a - 3, 2))
                        : a <= 10
                        ? (ep(e, 17, e.bl_tree), eP(e, a - 3, 3))
                        : (ep(e, 18, e.bl_tree), eP(e, a - 11, 7));
                    (o = n),
                      (u =
                        (a = 0) === s
                          ? ((c = 138), 3)
                          : n === s
                          ? ((c = 6), 3)
                          : ((c = 7), 4));
                  }
              }
              function ek(e, t, r, i) {
                eP(e, 0 + +!!i, 3),
                  e_(e),
                  eR(e, r),
                  eR(e, ~r),
                  r &&
                    e.pending_buf.set(e.window.subarray(t, t + r), e.pending),
                  (e.pending += r);
              }
              function ex(e, t) {
                return (e.msg = eW[t]), t;
              }
              function eE(e) {
                return 2 * e - 9 * (4 < e);
              }
              function eO(e, t) {
                eX(
                  e,
                  0 <= e.block_start ? e.block_start : -1,
                  e.strstart - e.block_start,
                  t
                ),
                  (e.block_start = e.strstart),
                  tu(e.strm);
              }
              function eD(e, t) {
                e.pending_buf[e.pending++] = t;
              }
              function eT(e, t) {
                (e.pending_buf[e.pending++] = (t >>> 8) & 255),
                  (e.pending_buf[e.pending++] = 255 & t);
              }
              function eC(e, t) {
                var r,
                  i,
                  n = e.max_chain_length,
                  o = e.strstart,
                  s = e.prev_length,
                  a = e.nice_match,
                  c =
                    e.w_size - 262 < e.strstart
                      ? e.strstart - (e.w_size - 262)
                      : 0,
                  u = e.window,
                  l = e.w_mask,
                  f = e.prev,
                  h = e.strstart + 258,
                  d = u[o + s - 1],
                  p = u[o + s];
                e.good_match <= e.prev_length && (n >>= 2),
                  e.lookahead < a && (a = e.lookahead);
                do
                  if (
                    u[(r = t) + s] === p &&
                    u[r + s - 1] === d &&
                    u[r] === u[o] &&
                    u[++r] === u[o + 1]
                  ) {
                    for (
                      o += 2, r++;
                      u[++o] === u[++r] &&
                      u[++o] === u[++r] &&
                      u[++o] === u[++r] &&
                      u[++o] === u[++r] &&
                      u[++o] === u[++r] &&
                      u[++o] === u[++r] &&
                      u[++o] === u[++r] &&
                      u[++o] === u[++r] &&
                      o < h;

                    );
                    if (((i = 258 - (h - o)), (o = h - 258), s < i)) {
                      if (((e.match_start = t), a <= (s = i))) break;
                      (d = u[o + s - 1]), (p = u[o + s]);
                    }
                  }
                while ((t = f[t & l]) > c && 0 != --n);
                return s <= e.lookahead ? s : e.lookahead;
              }
              function eA(e) {
                var t,
                  r,
                  i = e.w_size;
                do {
                  if (
                    ((t = e.window_size - e.lookahead - e.strstart),
                    i + (i - 262) <= e.strstart &&
                      (e.window.set(e.window.subarray(i, i + i - t), 0),
                      (e.match_start -= i),
                      (e.strstart -= i),
                      (e.block_start -= i),
                      e.strstart < e.insert && (e.insert = e.strstart),
                      ta(e),
                      (t += i)),
                    0 === e.strm.avail_in)
                  )
                    break;
                  if (
                    ((t = tl(e.strm, e.window, e.strstart + e.lookahead, t)),
                    (e.lookahead += t),
                    3 <= e.lookahead + e.insert)
                  )
                    for (
                      r = e.strstart - e.insert,
                        e.ins_h = e.window[r],
                        e.ins_h = tc(e, e.ins_h, e.window[r + 1]);
                      e.insert &&
                      ((e.ins_h = tc(e, e.ins_h, e.window[r + 3 - 1])),
                      (e.prev[r & e.w_mask] = e.head[e.ins_h]),
                      (e.head[e.ins_h] = r),
                      r++,
                      e.insert--,
                      !(e.lookahead + e.insert < 3));

                    );
                } while (e.lookahead < 262 && 0 !== e.strm.avail_in);
              }
              function eI(e, t) {
                for (
                  var r,
                    i,
                    n,
                    o =
                      e.pending_buf_size - 5 > e.w_size
                        ? e.w_size
                        : e.pending_buf_size - 5,
                    s = 0,
                    a = e.strm.avail_in;
                  (r = 65535),
                    (n = (e.bi_valid + 42) >> 3),
                    !(
                      e.strm.avail_out < n ||
                      ((r =
                        (n = e.strm.avail_out - n) <
                        (r =
                          r > (i = e.strstart - e.block_start) + e.strm.avail_in
                            ? i + e.strm.avail_in
                            : r)
                          ? n
                          : r) < o &&
                        ((0 === r && t !== e2) ||
                          t === eY ||
                          r !== i + e.strm.avail_in)) ||
                      ((s = +(t === e2 && r === i + e.strm.avail_in)),
                      eZ(e, 0, 0, s),
                      (e.pending_buf[e.pending - 4] = r),
                      (e.pending_buf[e.pending - 3] = r >> 8),
                      (e.pending_buf[e.pending - 2] = ~r),
                      (e.pending_buf[e.pending - 1] = ~r >> 8),
                      tu(e.strm),
                      i &&
                        (r < i && (i = r),
                        e.strm.output.set(
                          e.window.subarray(e.block_start, e.block_start + i),
                          e.strm.next_out
                        ),
                        (e.strm.next_out += i),
                        (e.strm.avail_out -= i),
                        (e.strm.total_out += i),
                        (e.block_start += i),
                        (r -= i)),
                      r &&
                        (tl(e.strm, e.strm.output, e.strm.next_out, r),
                        (e.strm.next_out += r),
                        (e.strm.avail_out -= r),
                        (e.strm.total_out += r)),
                      0 !== s)
                    );

                );
                return (
                  (a -= e.strm.avail_in) &&
                    (a >= e.w_size
                      ? ((e.matches = 2),
                        e.window.set(
                          e.strm.input.subarray(
                            e.strm.next_in - e.w_size,
                            e.strm.next_in
                          ),
                          0
                        ),
                        (e.strstart = e.w_size),
                        (e.insert = e.strstart))
                      : (e.window_size - e.strstart <= a &&
                          ((e.strstart -= e.w_size),
                          e.window.set(
                            e.window.subarray(e.w_size, e.w_size + e.strstart),
                            0
                          ),
                          e.matches < 2 && e.matches++,
                          e.strstart < e.insert) &&
                          (e.insert = e.strstart),
                        e.window.set(
                          e.strm.input.subarray(
                            e.strm.next_in - a,
                            e.strm.next_in
                          ),
                          e.strstart
                        ),
                        (e.strstart += a),
                        (e.insert +=
                          e.w_size - e.insert < a ? e.w_size - e.insert : a)),
                    (e.block_start = e.strstart)),
                  e.high_water < e.strstart && (e.high_water = e.strstart),
                  s
                    ? 4
                    : t !== eY &&
                      t !== e2 &&
                      0 === e.strm.avail_in &&
                      e.strstart === e.block_start
                    ? 2
                    : ((n = e.window_size - e.strstart),
                      e.strm.avail_in > n &&
                        e.block_start >= e.w_size &&
                        ((e.block_start -= e.w_size),
                        (e.strstart -= e.w_size),
                        e.window.set(
                          e.window.subarray(e.w_size, e.w_size + e.strstart),
                          0
                        ),
                        e.matches < 2 && e.matches++,
                        (n += e.w_size),
                        e.strstart < e.insert) &&
                        (e.insert = e.strstart),
                      (n = n > e.strm.avail_in ? e.strm.avail_in : n) &&
                        (tl(e.strm, e.window, e.strstart, n),
                        (e.strstart += n),
                        (e.insert +=
                          e.w_size - e.insert < n ? e.w_size - e.insert : n)),
                      e.high_water < e.strstart && (e.high_water = e.strstart),
                      (o =
                        (n =
                          65535 <
                          e.pending_buf_size - (n = (e.bi_valid + 42) >> 3)
                            ? 65535
                            : e.pending_buf_size - n) > e.w_size
                          ? e.w_size
                          : n),
                      ((i = e.strstart - e.block_start) >= o ||
                        ((i || t === e2) &&
                          t !== eY &&
                          0 === e.strm.avail_in &&
                          i <= n)) &&
                        ((r = n < i ? n : i),
                        (s = +(t === e2 && 0 === e.strm.avail_in && r === i)),
                        eZ(e, e.block_start, r, s),
                        (e.block_start += r),
                        tu(e.strm)),
                      s ? 3 : 1)
                );
              }
              function ej(e, t) {
                for (var r, i; ; ) {
                  if (e.lookahead < 262) {
                    if ((eA(e), e.lookahead < 262 && t === eY)) return 1;
                    if (0 === e.lookahead) break;
                  }
                  if (
                    ((r = 0),
                    3 <= e.lookahead &&
                      ((e.ins_h = tc(e, e.ins_h, e.window[e.strstart + 3 - 1])),
                      (r = e.prev[e.strstart & e.w_mask] = e.head[e.ins_h]),
                      (e.head[e.ins_h] = e.strstart)),
                    0 !== r &&
                      e.strstart - r <= e.w_size - 262 &&
                      (e.match_length = eC(e, r)),
                    3 <= e.match_length)
                  ) {
                    if (
                      ((i = eQ(
                        e,
                        e.strstart - e.match_start,
                        e.match_length - 3
                      )),
                      (e.lookahead -= e.match_length),
                      e.match_length <= e.max_lazy_match && 3 <= e.lookahead)
                    ) {
                      for (
                        e.match_length--;
                        e.strstart++,
                          (e.ins_h = tc(
                            e,
                            e.ins_h,
                            e.window[e.strstart + 3 - 1]
                          )),
                          (r = e.prev[e.strstart & e.w_mask] = e.head[e.ins_h]),
                          (e.head[e.ins_h] = e.strstart),
                          0 != --e.match_length;

                      );
                      e.strstart++;
                    } else
                      (e.strstart += e.match_length),
                        (e.match_length = 0),
                        (e.ins_h = e.window[e.strstart]),
                        (e.ins_h = tc(e, e.ins_h, e.window[e.strstart + 1]));
                  } else
                    (i = eQ(e, 0, e.window[e.strstart])),
                      e.lookahead--,
                      e.strstart++;
                  if (i && (eO(e, !1), 0 === e.strm.avail_out)) return 1;
                }
                return (
                  (e.insert = e.strstart < 2 ? e.strstart : 2),
                  t === e2
                    ? (eO(e, !0), 0 === e.strm.avail_out ? 3 : 4)
                    : e.sym_next && (eO(e, !1), 0 === e.strm.avail_out)
                    ? 1
                    : 2
                );
              }
              function eB(e, t) {
                for (var r, i, n; ; ) {
                  if (e.lookahead < 262) {
                    if ((eA(e), e.lookahead < 262 && t === eY)) return 1;
                    if (0 === e.lookahead) break;
                  }
                  if (
                    ((r = 0),
                    3 <= e.lookahead &&
                      ((e.ins_h = tc(e, e.ins_h, e.window[e.strstart + 3 - 1])),
                      (r = e.prev[e.strstart & e.w_mask] = e.head[e.ins_h]),
                      (e.head[e.ins_h] = e.strstart)),
                    (e.prev_length = e.match_length),
                    (e.prev_match = e.match_start),
                    (e.match_length = 2),
                    0 !== r &&
                      e.prev_length < e.max_lazy_match &&
                      e.strstart - r <= e.w_size - 262 &&
                      ((e.match_length = eC(e, r)), e.match_length <= 5) &&
                      (e.strategy === te ||
                        (3 === e.match_length &&
                          4096 < e.strstart - e.match_start)) &&
                      (e.match_length = 2),
                    3 <= e.prev_length && e.match_length <= e.prev_length)
                  ) {
                    for (
                      n = e.strstart + e.lookahead - 3,
                        i = eQ(
                          e,
                          e.strstart - 1 - e.prev_match,
                          e.prev_length - 3
                        ),
                        e.lookahead -= e.prev_length - 1,
                        e.prev_length -= 2;
                      ++e.strstart <= n &&
                        ((e.ins_h = tc(
                          e,
                          e.ins_h,
                          e.window[e.strstart + 3 - 1]
                        )),
                        (r = e.prev[e.strstart & e.w_mask] = e.head[e.ins_h]),
                        (e.head[e.ins_h] = e.strstart)),
                        0 != --e.prev_length;

                    );
                    if (
                      ((e.match_available = 0),
                      (e.match_length = 2),
                      e.strstart++,
                      i && (eO(e, !1), 0 === e.strm.avail_out))
                    )
                      return 1;
                  } else if (e.match_available) {
                    if (
                      ((i = eQ(e, 0, e.window[e.strstart - 1])) && eO(e, !1),
                      e.strstart++,
                      e.lookahead--,
                      0 === e.strm.avail_out)
                    )
                      return 1;
                  } else (e.match_available = 1), e.strstart++, e.lookahead--;
                }
                return (
                  e.match_available &&
                    ((i = eQ(e, 0, e.window[e.strstart - 1])),
                    (e.match_available = 0)),
                  (e.insert = e.strstart < 2 ? e.strstart : 2),
                  t === e2
                    ? (eO(e, !0), 0 === e.strm.avail_out ? 3 : 4)
                    : e.sym_next && (eO(e, !1), 0 === e.strm.avail_out)
                    ? 1
                    : 2
                );
              }
              Q(el);
              var eR = function (e, t) {
                  (e.pending_buf[e.pending++] = 255 & t),
                    (e.pending_buf[e.pending++] = (t >>> 8) & 255);
                },
                eP = function (e, t, r) {
                  e.bi_valid > 16 - r
                    ? ((e.bi_buf |= (t << e.bi_valid) & 65535),
                      eR(e, e.bi_buf),
                      (e.bi_buf = t >> (16 - e.bi_valid)),
                      (e.bi_valid += r - 16))
                    : ((e.bi_buf |= (t << e.bi_valid) & 65535),
                      (e.bi_valid += r));
                },
                eU = function (e, t, r, i) {
                  var n = 2 * t,
                    o = 2 * r;
                  return e[n] < e[o] || (e[n] === e[o] && i[t] <= i[r]);
                },
                eM = !1,
                eG = function (e) {
                  eM ||
                    ((() => {
                      for (
                        var e, t, r, i = Array(16), n = 0, o = 0;
                        o < 28;
                        o++
                      )
                        for (es[o] = n, e = 0; e < 1 << $[o]; e++) eo[n++] = o;
                      for (eo[n - 1] = o, o = r = 0; o < 16; o++)
                        for (el[o] = r, e = 0; e < 1 << Y[o]; e++) en[r++] = o;
                      for (r >>= 7; o < 30; o++)
                        for (el[o] = r << 7, e = 0; e < 1 << (Y[o] - 7); e++)
                          en[256 + r++] = o;
                      for (t = 0; t <= 15; t++) i[t] = 0;
                      for (e = 0; e <= 143; ) (er[2 * e + 1] = 8), e++, i[8]++;
                      for (; e <= 255; ) (er[2 * e + 1] = 9), e++, i[9]++;
                      for (; e <= 279; ) (er[2 * e + 1] = 7), e++, i[7]++;
                      for (; e <= 287; ) (er[2 * e + 1] = 8), e++, i[8]++;
                      for (em(er, 287, i), e = 0; e < 30; e++)
                        (ei[2 * e + 1] = 5), (ei[2 * e] = eg(e, 5));
                      (ea = new ef(er, $, 257, 286, 15)),
                        (ec = new ef(ei, Y, 0, 30, 15)),
                        (eu = new ef([], ee, 0, 19, 7));
                    })(),
                    (eM = !0)),
                    (e.l_desc = new eh(e.dyn_ltree, ea)),
                    (e.d_desc = new eh(e.dyn_dtree, ec)),
                    (e.bl_desc = new eh(e.bl_tree, eu)),
                    (e.bi_buf = 0),
                    (e.bi_valid = 0),
                    ey(e);
                },
                t = ek,
                eF = function (e, t, r, i) {
                  var n,
                    o,
                    s = 0;
                  0 < e.level
                    ? (2 === e.strm.data_type &&
                        (e.strm.data_type = ((e) => {
                          for (
                            var t = 0xf3ffc07f, r = 0;
                            r <= 31;
                            r++, t >>>= 1
                          )
                            if (1 & t && 0 !== e.dyn_ltree[2 * r]) return 0;
                          if (
                            0 !== e.dyn_ltree[18] ||
                            0 !== e.dyn_ltree[20] ||
                            0 !== e.dyn_ltree[26]
                          )
                            return 1;
                          for (r = 32; r < 256; r++)
                            if (0 !== e.dyn_ltree[2 * r]) return 1;
                          return 0;
                        })(e)),
                      ez(e, e.l_desc),
                      ez(e, e.d_desc),
                      (s = ((e) => {
                        var t;
                        for (
                          eS(e, e.dyn_ltree, e.l_desc.max_code),
                            eS(e, e.dyn_dtree, e.d_desc.max_code),
                            ez(e, e.bl_desc),
                            t = 18;
                          3 <= t && 0 === e.bl_tree[2 * et[t] + 1];
                          t--
                        );
                        return (e.opt_len += 3 * (t + 1) + 5 + 5 + 4), t;
                      })(e)),
                      (o = (e.static_len + 3 + 7) >>> 3) <=
                        (n = (e.opt_len + 3 + 7) >>> 3) && (n = o))
                    : (n = o = r + 5),
                    r + 4 <= n && -1 !== t
                      ? ek(e, t, r, i)
                      : 4 === e.strategy || o === n
                      ? (eP(e, 2 + +!!i, 3), ev(e, er, ei))
                      : (eP(e, 4 + +!!i, 3),
                        ((e, t, r, i) => {
                          var n;
                          for (
                            eP(e, t - 257, 5),
                              eP(e, r - 1, 5),
                              eP(e, i - 4, 4),
                              n = 0;
                            n < i;
                            n++
                          )
                            eP(e, e.bl_tree[2 * et[n] + 1], 3);
                          ew(e, e.dyn_ltree, t - 1), ew(e, e.dyn_dtree, r - 1);
                        })(
                          e,
                          e.l_desc.max_code + 1,
                          e.d_desc.max_code + 1,
                          s + 1
                        ),
                        ev(e, e.dyn_ltree, e.dyn_dtree)),
                    ey(e),
                    i && e_(e);
                },
                eN = function (e, t, r) {
                  return (
                    (e.pending_buf[e.sym_buf + e.sym_next++] = t),
                    (e.pending_buf[e.sym_buf + e.sym_next++] = t >> 8),
                    (e.pending_buf[e.sym_buf + e.sym_next++] = r),
                    0 === t
                      ? e.dyn_ltree[2 * r]++
                      : (e.matches++,
                        t--,
                        e.dyn_ltree[2 * (eo[r] + 256 + 1)]++,
                        e.dyn_dtree[2 * ed(t)]++),
                    e.sym_next === e.sym_end
                  );
                },
                eH = function (e) {
                  eP(e, 2, 3),
                    ep(e, 256, er),
                    16 === e.bi_valid
                      ? (eR(e, e.bi_buf), (e.bi_buf = 0), (e.bi_valid = 0))
                      : 8 <= e.bi_valid &&
                        ((e.pending_buf[e.pending++] = 255 & e.bi_buf),
                        (e.bi_buf >>= 8),
                        (e.bi_valid -= 8));
                },
                eL = function (e, t, r, i) {
                  for (
                    var n = (65535 & e) | 0,
                      o = ((e >>> 16) & 65535) | 0,
                      s = 0;
                    0 !== r;

                  ) {
                    for (
                      r -= s = 2e3 < r ? 2e3 : r;
                      (o = (o + (n = (n + t[i++]) | 0)) | 0), --s;

                    );
                    (n %= 65521), (o %= 65521);
                  }
                  return n | (o << 16) | 0;
                },
                eK = new Uint32Array(
                  (() => {
                    for (var e = [], t = 0; t < 256; t++) {
                      for (var r = t, i = 0; i < 8; i++)
                        r = 1 & r ? 0xedb88320 ^ (r >>> 1) : r >>> 1;
                      e[t] = r;
                    }
                    return e;
                  })()
                ),
                eq = function (e, t, r, i) {
                  var n = i + r;
                  e ^= -1;
                  for (var o = i; o < n; o++)
                    e = (e >>> 8) ^ eK[255 & (e ^ t[o])];
                  return -1 ^ e;
                },
                eW = {
                  2: "need dictionary",
                  1: "stream end",
                  0: "",
                  "-1": "file error",
                  "-2": "stream error",
                  "-3": "data error",
                  "-4": "insufficient memory",
                  "-5": "buffer error",
                  "-6": "incompatible version",
                },
                eV = {
                  Z_NO_FLUSH: 0,
                  Z_PARTIAL_FLUSH: 1,
                  Z_SYNC_FLUSH: 2,
                  Z_FULL_FLUSH: 3,
                  Z_FINISH: 4,
                  Z_BLOCK: 5,
                  Z_TREES: 6,
                  Z_OK: 0,
                  Z_STREAM_END: 1,
                  Z_NEED_DICT: 2,
                  Z_ERRNO: -1,
                  Z_STREAM_ERROR: -2,
                  Z_DATA_ERROR: -3,
                  Z_MEM_ERROR: -4,
                  Z_BUF_ERROR: -5,
                  Z_NO_COMPRESSION: 0,
                  Z_BEST_SPEED: 1,
                  Z_BEST_COMPRESSION: 9,
                  Z_DEFAULT_COMPRESSION: -1,
                  Z_FILTERED: 1,
                  Z_HUFFMAN_ONLY: 2,
                  Z_RLE: 3,
                  Z_FIXED: 4,
                  Z_DEFAULT_STRATEGY: 0,
                  Z_BINARY: 0,
                  Z_TEXT: 1,
                  Z_UNKNOWN: 2,
                  Z_DEFLATED: 8,
                },
                eJ = eG,
                eZ = t,
                eX = eF,
                eQ = eN,
                e$ = eH,
                eY = eV.Z_NO_FLUSH,
                e1 = eV.Z_PARTIAL_FLUSH,
                e0 = eV.Z_FULL_FLUSH,
                e2 = eV.Z_FINISH,
                e4 = eV.Z_BLOCK,
                e3 = eV.Z_OK,
                e5 = eV.Z_STREAM_END,
                e6 = eV.Z_STREAM_ERROR,
                e8 = eV.Z_DATA_ERROR,
                e9 = eV.Z_BUF_ERROR,
                e7 = eV.Z_DEFAULT_COMPRESSION,
                te = eV.Z_FILTERED,
                tt = eV.Z_HUFFMAN_ONLY,
                tr = eV.Z_RLE,
                ti = eV.Z_FIXED,
                tn = eV.Z_UNKNOWN,
                to = eV.Z_DEFLATED,
                ts = function (e) {
                  for (var t = e.length; 0 <= --t; ) e[t] = 0;
                },
                ta = function (e) {
                  for (
                    var t, r, i = e.w_size, n = (t = e.hash_size);
                    (r = e.head[--n]), (e.head[n] = i <= r ? r - i : 0), --t;

                  );
                  for (
                    n = t = i;
                    (r = e.prev[--n]), (e.prev[n] = i <= r ? r - i : 0), --t;

                  );
                },
                tc = function (e, t, r) {
                  return ((t << e.hash_shift) ^ r) & e.hash_mask;
                },
                tu = function (e) {
                  var t = e.state,
                    r = t.pending;
                  0 !== (r = e.avail_out < r ? e.avail_out : r) &&
                    (e.output.set(
                      t.pending_buf.subarray(t.pending_out, t.pending_out + r),
                      e.next_out
                    ),
                    (e.next_out += r),
                    (t.pending_out += r),
                    (e.total_out += r),
                    (e.avail_out -= r),
                    (t.pending -= r),
                    0 === t.pending) &&
                    (t.pending_out = 0);
                },
                tl = function (e, t, r, i) {
                  var n = e.avail_in;
                  return 0 === (n = i < n ? i : n)
                    ? 0
                    : ((e.avail_in -= n),
                      t.set(e.input.subarray(e.next_in, e.next_in + n), r),
                      1 === e.state.wrap
                        ? (e.adler = eL(e.adler, t, n, r))
                        : 2 === e.state.wrap &&
                          (e.adler = eq(e.adler, t, n, r)),
                      (e.next_in += n),
                      (e.total_in += n),
                      n);
                };
              function tf(e, t, r, i, n) {
                (this.good_length = e),
                  (this.max_lazy = t),
                  (this.nice_length = r),
                  (this.max_chain = i),
                  (this.func = n);
              }
              var th = [
                new tf(0, 0, 0, 0, eI),
                new tf(4, 4, 8, 4, ej),
                new tf(4, 5, 16, 8, ej),
                new tf(4, 6, 32, 32, ej),
                new tf(4, 4, 16, 16, eB),
                new tf(8, 16, 32, 32, eB),
                new tf(8, 16, 128, 128, eB),
                new tf(8, 32, 128, 256, eB),
                new tf(32, 128, 258, 1024, eB),
                new tf(32, 258, 258, 4096, eB),
              ];
              function td() {
                (this.strm = null),
                  (this.status = 0),
                  (this.pending_buf = null),
                  (this.pending_buf_size = 0),
                  (this.pending_out = 0),
                  (this.pending = 0),
                  (this.wrap = 0),
                  (this.gzhead = null),
                  (this.gzindex = 0),
                  (this.method = to),
                  (this.last_flush = -1),
                  (this.w_size = 0),
                  (this.w_bits = 0),
                  (this.w_mask = 0),
                  (this.window = null),
                  (this.window_size = 0),
                  (this.prev = null),
                  (this.head = null),
                  (this.ins_h = 0),
                  (this.hash_size = 0),
                  (this.hash_bits = 0),
                  (this.hash_mask = 0),
                  (this.hash_shift = 0),
                  (this.block_start = 0),
                  (this.match_length = 0),
                  (this.prev_match = 0),
                  (this.match_available = 0),
                  (this.strstart = 0),
                  (this.match_start = 0),
                  (this.lookahead = 0),
                  (this.prev_length = 0),
                  (this.max_chain_length = 0),
                  (this.max_lazy_match = 0),
                  (this.level = 0),
                  (this.strategy = 0),
                  (this.good_match = 0),
                  (this.nice_match = 0),
                  (this.dyn_ltree = new Uint16Array(1146)),
                  (this.dyn_dtree = new Uint16Array(122)),
                  (this.bl_tree = new Uint16Array(78)),
                  ts(this.dyn_ltree),
                  ts(this.dyn_dtree),
                  ts(this.bl_tree),
                  (this.l_desc = null),
                  (this.d_desc = null),
                  (this.bl_desc = null),
                  (this.bl_count = new Uint16Array(16)),
                  (this.heap = new Uint16Array(573)),
                  ts(this.heap),
                  (this.heap_len = 0),
                  (this.heap_max = 0),
                  (this.depth = new Uint16Array(573)),
                  ts(this.depth),
                  (this.sym_buf = 0),
                  (this.lit_bufsize = 0),
                  (this.sym_next = 0),
                  (this.sym_end = 0),
                  (this.opt_len = 0),
                  (this.static_len = 0),
                  (this.matches = 0),
                  (this.insert = 0),
                  (this.bi_buf = 0),
                  (this.bi_valid = 0);
              }
              function tp(e) {
                var t;
                return e &&
                  (t = e.state) &&
                  t.strm === e &&
                  (42 === t.status ||
                    57 === t.status ||
                    69 === t.status ||
                    73 === t.status ||
                    91 === t.status ||
                    103 === t.status ||
                    113 === t.status ||
                    666 === t.status)
                  ? 0
                  : 1;
              }
              var tg = function (e) {
                  if (tp(e)) return ex(e, e6);
                  (e.total_in = e.total_out = 0), (e.data_type = tn);
                  var t = e.state;
                  return (
                    (t.pending = 0),
                    (t.pending_out = 0),
                    t.wrap < 0 && (t.wrap = -t.wrap),
                    (t.status = 2 === t.wrap ? 57 : t.wrap ? 42 : 113),
                    (e.adler = +(2 !== t.wrap)),
                    (t.last_flush = -2),
                    eJ(t),
                    e3
                  );
                },
                tm = function (e, t, r, i, n, o) {
                  if (!e) return e6;
                  var s,
                    a,
                    c = 1;
                  if (
                    (t === e7 && (t = 6),
                    i < 0
                      ? ((c = 0), (i = -i))
                      : 15 < i && ((c = 2), (i -= 16)),
                    n < 1 ||
                      9 < n ||
                      r !== to ||
                      i < 8 ||
                      15 < i ||
                      t < 0 ||
                      9 < t ||
                      o < 0 ||
                      ti < o ||
                      (8 === i && 1 !== c))
                  )
                    return ex(e, e6);
                  8 === i && (i = 9);
                  var u = new td();
                  return (
                    ((e.state = u).strm = e),
                    (u.status = 42),
                    (u.wrap = c),
                    (u.gzhead = null),
                    (u.w_bits = i),
                    (u.w_size = 1 << u.w_bits),
                    (u.w_mask = u.w_size - 1),
                    (u.hash_bits = n + 7),
                    (u.hash_size = 1 << u.hash_bits),
                    (u.hash_mask = u.hash_size - 1),
                    (u.hash_shift = ~~((u.hash_bits + 3 - 1) / 3)),
                    (u.window = new Uint8Array(2 * u.w_size)),
                    (u.head = new Uint16Array(u.hash_size)),
                    (u.prev = new Uint16Array(u.w_size)),
                    (u.lit_bufsize = 1 << (n + 6)),
                    (u.pending_buf_size = 4 * u.lit_bufsize),
                    (u.pending_buf = new Uint8Array(u.pending_buf_size)),
                    (u.sym_buf = u.lit_bufsize),
                    (u.sym_end = 3 * (u.lit_bufsize - 1)),
                    (u.level = t),
                    (u.strategy = o),
                    (u.method = r),
                    (a = tg((s = e))) === e3 &&
                      (((s = s.state).window_size = 2 * s.w_size),
                      ts(s.head),
                      (s.max_lazy_match = th[s.level].max_lazy),
                      (s.good_match = th[s.level].good_length),
                      (s.nice_match = th[s.level].nice_length),
                      (s.max_chain_length = th[s.level].max_chain),
                      (s.strstart = 0),
                      (s.block_start = 0),
                      (s.lookahead = 0),
                      (s.insert = 0),
                      (s.match_length = s.prev_length = 2),
                      (s.match_available = 0),
                      (s.ins_h = 0)),
                    a
                  );
                },
                ty = function (e, t) {
                  if (tp(e) || e4 < t || t < 0) return e ? ex(e, e6) : e6;
                  var r = e.state;
                  if (
                    !e.output ||
                    (0 !== e.avail_in && !e.input) ||
                    (666 === r.status && t !== e2)
                  )
                    return ex(e, 0 === e.avail_out ? e9 : e6);
                  var i = r.last_flush;
                  if (((r.last_flush = t), 0 !== r.pending)) {
                    if ((tu(e), 0 === e.avail_out))
                      return (r.last_flush = -1), e3;
                  } else if (0 === e.avail_in && eE(t) <= eE(i) && t !== e2)
                    return ex(e, e9);
                  if (666 === r.status && 0 !== e.avail_in) return ex(e, e9);
                  if (
                    (42 === r.status && 0 === r.wrap && (r.status = 113),
                    42 === r.status &&
                      ((i =
                        ((to + ((r.w_bits - 8) << 4)) << 8) |
                        ((r.strategy >= tt || r.level < 2
                          ? 0
                          : r.level < 6
                          ? 1
                          : 6 === r.level
                          ? 2
                          : 3) <<
                          6)),
                      0 !== r.strstart && (i |= 32),
                      eT(r, (i += 31 - (i % 31))),
                      0 !== r.strstart &&
                        (eT(r, e.adler >>> 16), eT(r, 65535 & e.adler)),
                      (e.adler = 1),
                      (r.status = 113),
                      tu(e),
                      0 !== r.pending))
                  )
                    return (r.last_flush = -1), e3;
                  if (57 === r.status) {
                    if (
                      ((e.adler = 0), eD(r, 31), eD(r, 139), eD(r, 8), r.gzhead)
                    )
                      eD(
                        r,
                        +!!r.gzhead.text +
                          2 * !!r.gzhead.hcrc +
                          4 * !!r.gzhead.extra +
                          8 * !!r.gzhead.name +
                          16 * !!r.gzhead.comment
                      ),
                        eD(r, 255 & r.gzhead.time),
                        eD(r, (r.gzhead.time >> 8) & 255),
                        eD(r, (r.gzhead.time >> 16) & 255),
                        eD(r, (r.gzhead.time >> 24) & 255),
                        eD(
                          r,
                          9 === r.level
                            ? 2
                            : 4 * (r.strategy >= tt || r.level < 2)
                        ),
                        eD(r, 255 & r.gzhead.os),
                        r.gzhead.extra &&
                          r.gzhead.extra.length &&
                          (eD(r, 255 & r.gzhead.extra.length),
                          eD(r, (r.gzhead.extra.length >> 8) & 255)),
                        r.gzhead.hcrc &&
                          (e.adler = eq(e.adler, r.pending_buf, r.pending, 0)),
                        (r.gzindex = 0),
                        (r.status = 69);
                    else if (
                      (eD(r, 0),
                      eD(r, 0),
                      eD(r, 0),
                      eD(r, 0),
                      eD(r, 0),
                      eD(
                        r,
                        9 === r.level
                          ? 2
                          : 4 * (r.strategy >= tt || r.level < 2)
                      ),
                      eD(r, 3),
                      (r.status = 113),
                      tu(e),
                      0 !== r.pending)
                    )
                      return (r.last_flush = -1), e3;
                  }
                  if (69 === r.status) {
                    if (r.gzhead.extra) {
                      for (
                        var n = r.pending,
                          o = (65535 & r.gzhead.extra.length) - r.gzindex;
                        r.pending + o > r.pending_buf_size;

                      ) {
                        var s = r.pending_buf_size - r.pending;
                        if (
                          (r.pending_buf.set(
                            r.gzhead.extra.subarray(r.gzindex, r.gzindex + s),
                            r.pending
                          ),
                          (r.pending = r.pending_buf_size),
                          r.gzhead.hcrc &&
                            r.pending > n &&
                            (e.adler = eq(
                              e.adler,
                              r.pending_buf,
                              r.pending - n,
                              n
                            )),
                          (r.gzindex += s),
                          tu(e),
                          0 !== r.pending)
                        )
                          return (r.last_flush = -1), e3;
                        (n = 0), (o -= s);
                      }
                      (i = new Uint8Array(r.gzhead.extra)),
                        r.pending_buf.set(
                          i.subarray(r.gzindex, r.gzindex + o),
                          r.pending
                        ),
                        (r.pending += o),
                        r.gzhead.hcrc &&
                          r.pending > n &&
                          (e.adler = eq(
                            e.adler,
                            r.pending_buf,
                            r.pending - n,
                            n
                          )),
                        (r.gzindex = 0);
                    }
                    r.status = 73;
                  }
                  if (73 === r.status) {
                    if (r.gzhead.name) {
                      var a,
                        c = r.pending;
                      do
                        if (r.pending === r.pending_buf_size) {
                          if (
                            (r.gzhead.hcrc &&
                              r.pending > c &&
                              (e.adler = eq(
                                e.adler,
                                r.pending_buf,
                                r.pending - c,
                                c
                              )),
                            tu(e),
                            0 !== r.pending)
                          )
                            return (r.last_flush = -1), e3;
                          c = 0;
                        }
                      while (
                        ((a =
                          r.gzindex < r.gzhead.name.length
                            ? 255 & r.gzhead.name.charCodeAt(r.gzindex++)
                            : 0),
                        eD(r, a),
                        0 != a)
                      );
                      r.gzhead.hcrc &&
                        r.pending > c &&
                        (e.adler = eq(
                          e.adler,
                          r.pending_buf,
                          r.pending - c,
                          c
                        )),
                        (r.gzindex = 0);
                    }
                    r.status = 91;
                  }
                  if (91 === r.status) {
                    if (r.gzhead.comment) {
                      var u,
                        l = r.pending;
                      do
                        if (r.pending === r.pending_buf_size) {
                          if (
                            (r.gzhead.hcrc &&
                              r.pending > l &&
                              (e.adler = eq(
                                e.adler,
                                r.pending_buf,
                                r.pending - l,
                                l
                              )),
                            tu(e),
                            0 !== r.pending)
                          )
                            return (r.last_flush = -1), e3;
                          l = 0;
                        }
                      while (
                        ((u =
                          r.gzindex < r.gzhead.comment.length
                            ? 255 & r.gzhead.comment.charCodeAt(r.gzindex++)
                            : 0),
                        eD(r, u),
                        0 != u)
                      );
                      r.gzhead.hcrc &&
                        r.pending > l &&
                        (e.adler = eq(
                          e.adler,
                          r.pending_buf,
                          r.pending - l,
                          l
                        ));
                    }
                    r.status = 103;
                  }
                  if (103 === r.status) {
                    if (r.gzhead.hcrc) {
                      if (
                        r.pending + 2 > r.pending_buf_size &&
                        (tu(e), 0 !== r.pending)
                      )
                        return (r.last_flush = -1), e3;
                      eD(r, 255 & e.adler),
                        eD(r, (e.adler >> 8) & 255),
                        (e.adler = 0);
                    }
                    if (((r.status = 113), tu(e), 0 !== r.pending))
                      return (r.last_flush = -1), e3;
                  }
                  if (
                    0 !== e.avail_in ||
                    0 !== r.lookahead ||
                    (t !== eY && 666 !== r.status)
                  ) {
                    if (
                      ((3 !==
                        (i =
                          0 === r.level
                            ? eI(r, t)
                            : r.strategy === tt
                            ? ((e, t) => {
                                for (var r; ; ) {
                                  if (
                                    0 === e.lookahead &&
                                    (eA(e), 0 === e.lookahead)
                                  ) {
                                    if (t === eY) return 1;
                                    break;
                                  }
                                  if (
                                    ((e.match_length = 0),
                                    (r = eQ(e, 0, e.window[e.strstart])),
                                    e.lookahead--,
                                    e.strstart++,
                                    r && (eO(e, !1), 0 === e.strm.avail_out))
                                  )
                                    return 1;
                                }
                                return (
                                  (e.insert = 0),
                                  t === e2
                                    ? (eO(e, !0),
                                      0 === e.strm.avail_out ? 3 : 4)
                                    : e.sym_next &&
                                      (eO(e, !1), 0 === e.strm.avail_out)
                                    ? 1
                                    : 2
                                );
                              })(r, t)
                            : r.strategy === tr
                            ? ((e, t) => {
                                for (var r, i, n, o, s = e.window; ; ) {
                                  if (e.lookahead <= 258) {
                                    if ((eA(e), e.lookahead <= 258 && t === eY))
                                      return 1;
                                    if (0 === e.lookahead) break;
                                  }
                                  if (
                                    ((e.match_length = 0),
                                    3 <= e.lookahead &&
                                      0 < e.strstart &&
                                      (i = s[(n = e.strstart - 1)]) ===
                                        s[++n] &&
                                      i === s[++n] &&
                                      i === s[++n])
                                  ) {
                                    for (
                                      o = e.strstart + 258;
                                      i === s[++n] &&
                                      i === s[++n] &&
                                      i === s[++n] &&
                                      i === s[++n] &&
                                      i === s[++n] &&
                                      i === s[++n] &&
                                      i === s[++n] &&
                                      i === s[++n] &&
                                      n < o;

                                    );
                                    (e.match_length = 258 - (o - n)),
                                      e.lookahead < e.match_length &&
                                        (e.match_length = e.lookahead);
                                  }
                                  if (
                                    (3 <= e.match_length
                                      ? ((r = eQ(e, 1, e.match_length - 3)),
                                        (e.lookahead -= e.match_length),
                                        (e.strstart += e.match_length),
                                        (e.match_length = 0))
                                      : ((r = eQ(e, 0, e.window[e.strstart])),
                                        e.lookahead--,
                                        e.strstart++),
                                    r && (eO(e, !1), 0 === e.strm.avail_out))
                                  )
                                    return 1;
                                }
                                return (
                                  (e.insert = 0),
                                  t === e2
                                    ? (eO(e, !0),
                                      0 === e.strm.avail_out ? 3 : 4)
                                    : e.sym_next &&
                                      (eO(e, !1), 0 === e.strm.avail_out)
                                    ? 1
                                    : 2
                                );
                              })(r, t)
                            : th[r.level].func(r, t)) &&
                        4 !== i) ||
                        (r.status = 666),
                      1 === i || 3 === i)
                    )
                      return 0 === e.avail_out && (r.last_flush = -1), e3;
                    if (
                      2 === i &&
                      (t === e1
                        ? e$(r)
                        : t !== e4 &&
                          (eZ(r, 0, 0, !1), t === e0) &&
                          (ts(r.head), 0 === r.lookahead) &&
                          ((r.strstart = 0),
                          (r.block_start = 0),
                          (r.insert = 0)),
                      tu(e),
                      0 === e.avail_out)
                    )
                      return (r.last_flush = -1), e3;
                  }
                  return t === e2 &&
                    (r.wrap <= 0 ||
                      (2 === r.wrap
                        ? (eD(r, 255 & e.adler),
                          eD(r, (e.adler >> 8) & 255),
                          eD(r, (e.adler >> 16) & 255),
                          eD(r, (e.adler >> 24) & 255),
                          eD(r, 255 & e.total_in),
                          eD(r, (e.total_in >> 8) & 255),
                          eD(r, (e.total_in >> 16) & 255),
                          eD(r, (e.total_in >> 24) & 255))
                        : (eT(r, e.adler >>> 16), eT(r, 65535 & e.adler)),
                      tu(e),
                      0 < r.wrap && (r.wrap = -r.wrap),
                      0 === r.pending))
                    ? e5
                    : e3;
                },
                t_ = function (e) {
                  var t;
                  return tp(e)
                    ? e6
                    : ((t = e.state.status),
                      (e.state = null),
                      113 === t ? ex(e, e8) : e3);
                },
                tb = function (e, t) {
                  var r = t.length;
                  if (tp(e)) return e6;
                  var i = e.state,
                    n = i.wrap;
                  if (2 === n || (1 === n && 42 !== i.status) || i.lookahead)
                    return e6;
                  1 === n && (e.adler = eL(e.adler, t, r, 0)),
                    (i.wrap = 0),
                    i.w_size <= r &&
                      (0 === n &&
                        (ts(i.head),
                        (i.strstart = 0),
                        (i.block_start = 0),
                        (i.insert = 0)),
                      (o = new Uint8Array(i.w_size)).set(
                        t.subarray(r - i.w_size, r),
                        0
                      ),
                      (t = o),
                      (r = i.w_size));
                  var o = e.avail_in,
                    s = e.next_in,
                    a = e.input;
                  for (
                    e.avail_in = r, e.next_in = 0, e.input = t, eA(i);
                    3 <= i.lookahead;

                  ) {
                    for (
                      var c = i.strstart, u = i.lookahead - 2;
                      (i.ins_h = tc(i, i.ins_h, i.window[c + 3 - 1])),
                        (i.prev[c & i.w_mask] = i.head[i.ins_h]),
                        (i.head[i.ins_h] = c),
                        c++,
                        --u;

                    );
                    (i.strstart = c), (i.lookahead = 2), eA(i);
                  }
                  return (
                    (i.strstart += i.lookahead),
                    (i.block_start = i.strstart),
                    (i.insert = i.lookahead),
                    (i.lookahead = 0),
                    (i.match_length = i.prev_length = 2),
                    (i.match_available = 0),
                    (e.next_in = s),
                    (e.input = a),
                    (e.avail_in = o),
                    (i.wrap = n),
                    e3
                  );
                },
                tv = function (e) {
                  for (
                    var t = Array.prototype.slice.call(arguments, 1);
                    t.length;

                  ) {
                    var r = t.shift();
                    if (r) {
                      if ("object" != typeof r)
                        throw TypeError(r + "must be non-object");
                      for (var i in r)
                        Object.prototype.hasOwnProperty.call(r, i) &&
                          (e[i] = r[i]);
                    }
                  }
                  return e;
                },
                tz = function (e) {
                  for (var t = 0, r = 0, i = e.length; r < i; r++)
                    t += e[r].length;
                  for (
                    var n = new Uint8Array(t), o = 0, s = 0, a = e.length;
                    o < a;
                    o++
                  ) {
                    var c = e[o];
                    n.set(c, s), (s += c.length);
                  }
                  return n;
                },
                tS = !0;
              try {
                String.fromCharCode.apply(null, new Uint8Array(1));
              } catch (e) {
                tS = !1;
              }
              for (var tw = new Uint8Array(256), tk = 0; tk < 256; tk++)
                tw[tk] =
                  252 <= tk
                    ? 6
                    : 248 <= tk
                    ? 5
                    : 240 <= tk
                    ? 4
                    : 224 <= tk
                    ? 3
                    : 192 <= tk
                    ? 2
                    : 1;
              function tx() {
                (this.input = null),
                  (this.next_in = 0),
                  (this.avail_in = 0),
                  (this.total_in = 0),
                  (this.output = null),
                  (this.next_out = 0),
                  (this.avail_out = 0),
                  (this.total_out = 0),
                  (this.msg = ""),
                  (this.state = null),
                  (this.data_type = 2),
                  (this.adler = 0);
              }
              tw[254] = tw[254] = 1;
              var tE = function (e) {
                  if (
                    "function" == typeof TextEncoder &&
                    TextEncoder.prototype.encode
                  )
                    return new TextEncoder().encode(e);
                  for (var t, r, i, n, o = e.length, s = 0, a = 0; a < o; a++)
                    55296 == (64512 & (r = e.charCodeAt(a))) &&
                      a + 1 < o &&
                      56320 == (64512 & (i = e.charCodeAt(a + 1))) &&
                      ((r = 65536 + ((r - 55296) << 10) + (i - 56320)), a++),
                      (s += r < 128 ? 1 : r < 2048 ? 2 : r < 65536 ? 3 : 4);
                  for (t = new Uint8Array(s), a = n = 0; n < s; a++)
                    55296 == (64512 & (r = e.charCodeAt(a))) &&
                      a + 1 < o &&
                      56320 == (64512 & (i = e.charCodeAt(a + 1))) &&
                      ((r = 65536 + ((r - 55296) << 10) + (i - 56320)), a++),
                      r < 128
                        ? (t[n++] = r)
                        : (r < 2048
                            ? (t[n++] = 192 | (r >>> 6))
                            : (r < 65536
                                ? (t[n++] = 224 | (r >>> 12))
                                : ((t[n++] = 240 | (r >>> 18)),
                                  (t[n++] = 128 | ((r >>> 12) & 63))),
                              (t[n++] = 128 | ((r >>> 6) & 63))),
                          (t[n++] = 128 | (63 & r)));
                  return t;
                },
                tO = function (e, t) {
                  var r = t || e.length;
                  if (
                    "function" == typeof TextDecoder &&
                    TextDecoder.prototype.decode
                  )
                    return new TextDecoder().decode(e.subarray(0, t));
                  for (var i = Array(2 * r), n = 0, o = 0; o < r; ) {
                    var s = e[o++];
                    if (s < 128) i[n++] = s;
                    else {
                      var a = tw[s];
                      if (4 < a) (i[n++] = 65533), (o += a - 1);
                      else {
                        for (
                          s &= 2 === a ? 31 : 3 === a ? 15 : 7;
                          1 < a && o < r;

                        )
                          (s = (s << 6) | (63 & e[o++])), a--;
                        1 < a
                          ? (i[n++] = 65533)
                          : s < 65536
                          ? (i[n++] = s)
                          : ((s -= 65536),
                            (i[n++] = 55296 | ((s >> 10) & 1023)),
                            (i[n++] = 56320 | (1023 & s)));
                      }
                    }
                  }
                  return ((e, t) => {
                    if (t < 65534 && e.subarray && tS)
                      return String.fromCharCode.apply(
                        null,
                        e.length === t ? e : e.subarray(0, t)
                      );
                    for (var r = "", i = 0; i < t; i++)
                      r += String.fromCharCode(e[i]);
                    return r;
                  })(i, n);
                },
                tD = function (e, t) {
                  for (
                    var r =
                      (t = (t = t || e.length) > e.length ? e.length : t) - 1;
                    0 <= r && 128 == (192 & e[r]);

                  )
                    r--;
                  return !(r < 0) && 0 !== r && r + tw[e[r]] > t ? r : t;
                },
                tT = Object.prototype.toString,
                tC = eV.Z_NO_FLUSH,
                tA = eV.Z_SYNC_FLUSH,
                tI = eV.Z_FULL_FLUSH,
                tj = eV.Z_FINISH,
                tB = eV.Z_OK,
                tR = eV.Z_STREAM_END,
                tP = eV.Z_DEFAULT_COMPRESSION,
                tU = eV.Z_DEFAULT_STRATEGY,
                tM = eV.Z_DEFLATED;
              function tG(e) {
                this.options = tv(
                  {
                    level: tP,
                    method: tM,
                    chunkSize: 16384,
                    windowBits: 15,
                    memLevel: 8,
                    strategy: tU,
                  },
                  e || {}
                );
                var t,
                  r,
                  e = this.options,
                  i =
                    (e.raw && 0 < e.windowBits
                      ? (e.windowBits = -e.windowBits)
                      : e.gzip &&
                        0 < e.windowBits &&
                        e.windowBits < 16 &&
                        (e.windowBits += 16),
                    (this.err = 0),
                    (this.msg = ""),
                    (this.ended = !1),
                    (this.chunks = []),
                    (this.strm = new tx()),
                    (this.strm.avail_out = 0),
                    tm(
                      this.strm,
                      e.level,
                      e.method,
                      e.windowBits,
                      e.memLevel,
                      e.strategy
                    ));
                if (i !== tB) throw Error(eW[i]);
                if (
                  (e.header &&
                    ((t = this.strm),
                    (r = e.header),
                    tp(t) || 2 !== t.state.wrap || (t.state.gzhead = r)),
                  e.dictionary)
                ) {
                  if (
                    ((e =
                      "string" == typeof e.dictionary
                        ? tE(e.dictionary)
                        : "[object ArrayBuffer]" === tT.call(e.dictionary)
                        ? new Uint8Array(e.dictionary)
                        : e.dictionary),
                    (i = tb(this.strm, e)) !== tB)
                  )
                    throw Error(eW[i]);
                  this._dict_set = !0;
                }
              }
              function tF(e, t) {
                if (((t = new tG(t)).push(e, !0), t.err))
                  throw t.msg || eW[t.err];
                return t.result;
              }
              function tN(e, t, r, i, n, o, s, a) {
                for (
                  var c,
                    u,
                    l,
                    f,
                    h,
                    d,
                    p,
                    g,
                    m,
                    y = a.bits,
                    _ = 0,
                    b = 0,
                    v = 0,
                    z = 0,
                    S = 0,
                    w = 0,
                    k = 0,
                    x = 0,
                    E = 0,
                    O = 0,
                    D = null,
                    T = new Uint16Array(16),
                    C = new Uint16Array(16),
                    A = null,
                    _ = 0;
                  _ <= 15;
                  _++
                )
                  T[_] = 0;
                for (b = 0; b < i; b++) T[t[r + b]]++;
                for (S = y, z = 15; 1 <= z && 0 === T[z]; z--);
                if ((z < S && (S = z), 0 === z))
                  (n[o++] = 0x1400000), (n[o++] = 0x1400000), (a.bits = 1);
                else {
                  for (v = 1; v < z && 0 === T[v]; v++);
                  for (S < v && (S = v), _ = x = 1; _ <= 15; _++)
                    if ((x = (x << 1) - T[_]) < 0) return -1;
                  if (0 < x && (0 === e || 1 !== z)) return -1;
                  for (C[1] = 0, _ = 1; _ < 15; _++) C[_ + 1] = C[_] + T[_];
                  for (b = 0; b < i; b++)
                    0 !== t[r + b] && (s[C[t[r + b]]++] = b);
                  if (
                    ((d =
                      0 === e
                        ? ((D = A = s), 20)
                        : 1 === e
                        ? ((D = tL), (A = tK), 257)
                        : ((D = tq), (A = tW), 0)),
                    (_ = v),
                    (h = o),
                    (k = b = O = 0),
                    (l = -1),
                    (f = (E = 1 << (w = S)) - 1),
                    (1 === e && 852 < E) || (2 === e && 592 < E))
                  )
                    return 1;
                  for (;;) {
                    for (
                      m =
                        s[b] + 1 < d
                          ? ((g = 0), s[b])
                          : s[b] >= d
                          ? ((g = A[s[b] - d]), D[s[b] - d])
                          : ((g = 96), 0),
                        c = 1 << (p = _ - k),
                        v = u = 1 << w;
                      (n[h + (O >> k) + (u -= c)] =
                        (p << 24) | (g << 16) | m | 0),
                        0 !== u;

                    );
                    for (c = 1 << (_ - 1); O & c; ) c >>= 1;
                    if (
                      ((O = 0 !== c ? (O & (c - 1)) + c : 0), b++, 0 == --T[_])
                    ) {
                      if (_ === z) break;
                      _ = t[r + s[b]];
                    }
                    if (S < _ && (O & f) !== l) {
                      for (
                        h += v, x = 1 << (w = _ - (k = 0 === k ? S : k));
                        w + k < z && !((x -= T[w + k]) <= 0);

                      )
                        w++, (x <<= 1);
                      if (
                        ((E += 1 << w),
                        (1 === e && 852 < E) || (2 === e && 592 < E))
                      )
                        return 1;
                      n[(l = O & f)] = (S << 24) | (w << 16) | (h - o) | 0;
                    }
                  }
                  0 !== O && (n[h + O] = ((_ - k) << 24) | 4194304),
                    (a.bits = S);
                }
                return 0;
              }
              function tH(e) {
                return (
                  ((e >>> 24) & 255) +
                  ((e >>> 8) & 65280) +
                  ((65280 & e) << 8) +
                  ((255 & e) << 24)
                );
              }
              (tG.prototype.push = function (e, t) {
                var r,
                  i,
                  n = this.strm,
                  o = this.options.chunkSize;
                if (this.ended) return !1;
                for (
                  i = t === ~~t ? t : !0 === t ? tj : tC,
                    "string" == typeof e
                      ? (n.input = tE(e))
                      : "[object ArrayBuffer]" === tT.call(e)
                      ? (n.input = new Uint8Array(e))
                      : (n.input = e),
                    n.next_in = 0,
                    n.avail_in = n.input.length;
                  ;

                )
                  if (
                    (0 === n.avail_out &&
                      ((n.output = new Uint8Array(o)),
                      (n.next_out = 0),
                      (n.avail_out = o)),
                    (i === tA || i === tI) && n.avail_out <= 6)
                  )
                    this.onData(n.output.subarray(0, n.next_out)),
                      (n.avail_out = 0);
                  else {
                    if (ty(n, i) === tR)
                      return (
                        0 < n.next_out &&
                          this.onData(n.output.subarray(0, n.next_out)),
                        (r = t_(this.strm)),
                        this.onEnd(r),
                        (this.ended = !0),
                        r === tB
                      );
                    if (0 !== n.avail_out) {
                      if (0 < i && 0 < n.next_out)
                        this.onData(n.output.subarray(0, n.next_out)),
                          (n.avail_out = 0);
                      else if (0 === n.avail_in) break;
                    } else this.onData(n.output);
                  }
                return !0;
              }),
                (tG.prototype.onData = function (e) {
                  this.chunks.push(e);
                }),
                (tG.prototype.onEnd = function (e) {
                  e === tB && (this.result = tz(this.chunks)),
                    (this.chunks = []),
                    (this.err = e),
                    (this.msg = this.strm.msg);
                });
              var eG = {
                  Deflate: tG,
                  deflate: tF,
                  deflateRaw: function (e, t) {
                    return ((t = t || {}).raw = !0), tF(e, t);
                  },
                  gzip: function (e, t) {
                    return ((t = t || {}).gzip = !0), tF(e, t);
                  },
                  constants: eV,
                },
                tL = new Uint16Array([
                  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35,
                  43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0,
                ]),
                tK = new Uint8Array([
                  16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18,
                  18, 19, 19, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 16, 72,
                  78,
                ]),
                tq = new Uint16Array([
                  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
                  257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193,
                  12289, 16385, 24577, 0, 0,
                ]),
                tW = new Uint8Array([
                  16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22,
                  22, 23, 23, 24, 24, 25, 25, 26, 26, 27, 27, 28, 28, 29, 29,
                  64, 64,
                ]),
                tV = eV.Z_FINISH,
                tJ = eV.Z_BLOCK,
                tZ = eV.Z_TREES,
                tX = eV.Z_OK,
                tQ = eV.Z_STREAM_END,
                t$ = eV.Z_NEED_DICT,
                tY = eV.Z_STREAM_ERROR,
                t1 = eV.Z_DATA_ERROR,
                t0 = eV.Z_MEM_ERROR,
                t2 = eV.Z_BUF_ERROR,
                t4 = eV.Z_DEFLATED;
              function t3() {
                (this.strm = null),
                  (this.mode = 0),
                  (this.last = !1),
                  (this.wrap = 0),
                  (this.havedict = !1),
                  (this.flags = 0),
                  (this.dmax = 0),
                  (this.check = 0),
                  (this.total = 0),
                  (this.head = null),
                  (this.wbits = 0),
                  (this.wsize = 0),
                  (this.whave = 0),
                  (this.wnext = 0),
                  (this.window = null),
                  (this.hold = 0),
                  (this.bits = 0),
                  (this.length = 0),
                  (this.offset = 0),
                  (this.extra = 0),
                  (this.lencode = null),
                  (this.distcode = null),
                  (this.lenbits = 0),
                  (this.distbits = 0),
                  (this.ncode = 0),
                  (this.nlen = 0),
                  (this.ndist = 0),
                  (this.have = 0),
                  (this.next = null),
                  (this.lens = new Uint16Array(320)),
                  (this.work = new Uint16Array(288)),
                  (this.lendyn = null),
                  (this.distdyn = null),
                  (this.sane = 0),
                  (this.back = 0),
                  (this.was = 0);
              }
              function t5(e) {
                var t, r;
                return re(e)
                  ? tY
                  : (((t = e.state).wsize = 0),
                    (t.whave = 0),
                    (t.wnext = 0),
                    re(e)
                      ? tY
                      : ((r = e.state),
                        (e.total_in = e.total_out = r.total = 0),
                        (e.msg = ""),
                        r.wrap && (e.adler = 1 & r.wrap),
                        (r.mode = 16180),
                        (r.last = 0),
                        (r.havedict = 0),
                        (r.flags = -1),
                        (r.dmax = 32768),
                        (r.head = null),
                        (r.hold = 0),
                        (r.bits = 0),
                        (r.lencode = r.lendyn = new Int32Array(852)),
                        (r.distcode = r.distdyn = new Int32Array(592)),
                        (r.sane = 1),
                        (r.back = -1),
                        tX));
              }
              function t6(e, t, r, i) {
                var n;
                return (
                  null === (e = e.state).window &&
                    ((e.wsize = 1 << e.wbits),
                    (e.wnext = 0),
                    (e.whave = 0),
                    (e.window = new Uint8Array(e.wsize))),
                  e.wsize <= i
                    ? (e.window.set(t.subarray(r - e.wsize, r), 0),
                      (e.wnext = 0),
                      (e.whave = e.wsize))
                    : ((n = e.wsize - e.wnext) > i && (n = i),
                      e.window.set(t.subarray(r - i, r - i + n), e.wnext),
                      (i -= n)
                        ? (e.window.set(t.subarray(r - i, r), 0),
                          (e.wnext = i),
                          (e.whave = e.wsize))
                        : ((e.wnext += n),
                          e.wnext === e.wsize && (e.wnext = 0),
                          e.whave < e.wsize && (e.whave += n))),
                  0
                );
              }
              function t8() {
                (this.text = 0),
                  (this.time = 0),
                  (this.xflags = 0),
                  (this.os = 0),
                  (this.extra = null),
                  (this.extra_len = 0),
                  (this.name = ""),
                  (this.comment = ""),
                  (this.hcrc = 0),
                  (this.done = !1);
              }
              var t9,
                t7,
                re = function (e) {
                  var t;
                  return e &&
                    (t = e.state) &&
                    t.strm === e &&
                    !(t.mode < 16180) &&
                    !(16211 < t.mode)
                    ? 0
                    : 1;
                },
                rt = !0,
                rr = function (e, t) {
                  var r, i, n, o;
                  return e
                    ? ((r = new t3()),
                      ((e.state = r).strm = e),
                      (r.window = null),
                      (r.mode = 16180),
                      (i = t),
                      (r =
                        re(e) ||
                        ((o = e.state),
                        i < 0
                          ? ((n = 0), (i = -i))
                          : ((n = 5 + (i >> 4)), i < 48 && (i &= 15)),
                        i && (i < 8 || 15 < i))
                          ? tY
                          : (null !== o.window &&
                              o.wbits !== i &&
                              (o.window = null),
                            (o.wrap = n),
                            (o.wbits = i),
                            t5(e))) !== tX && (e.state = null),
                      r)
                    : tY;
                },
                ri = function (e, t) {
                  var r,
                    i,
                    n,
                    o,
                    s,
                    a,
                    c,
                    u,
                    l,
                    f,
                    h,
                    d,
                    p,
                    g,
                    m,
                    y,
                    _,
                    b,
                    v,
                    z,
                    S,
                    w,
                    k,
                    x,
                    E = 0,
                    O = new Uint8Array(4),
                    D = new Uint8Array([
                      16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14,
                      1, 15,
                    ]);
                  if (re(e) || !e.output || (!e.input && 0 !== e.avail_in))
                    return tY;
                  16191 === (r = e.state).mode && (r.mode = 16192),
                    (s = e.next_out),
                    (n = e.output),
                    (o = e.next_in),
                    (i = e.input),
                    (u = r.hold),
                    (l = r.bits),
                    (f = a = e.avail_in),
                    (h = c = e.avail_out),
                    (w = tX);
                  e: for (;;)
                    switch (r.mode) {
                      case 16180:
                        if (0 === r.wrap) r.mode = 16192;
                        else {
                          for (; l < 16; ) {
                            if (0 === a) break e;
                            a--, (u += i[o++] << l), (l += 8);
                          }
                          2 & r.wrap && 35615 === u
                            ? (0 === r.wbits && (r.wbits = 15),
                              (O[(r.check = 0)] = 255 & u),
                              (O[1] = (u >>> 8) & 255),
                              (r.check = eq(r.check, O, 2, 0)),
                              (l = u = 0),
                              (r.mode = 16181))
                            : (r.head && (r.head.done = !1),
                              !(1 & r.wrap) ||
                              (((255 & u) << 8) + (u >> 8)) % 31
                                ? ((e.msg = "incorrect header check"),
                                  (r.mode = 16209))
                                : (15 & u) !== t4
                                ? ((e.msg = "unknown compression method"),
                                  (r.mode = 16209))
                                : ((l -= 4),
                                  (S = 8 + (15 & (u >>>= 4))),
                                  0 === r.wbits && (r.wbits = S),
                                  15 < S || S > r.wbits
                                    ? ((e.msg = "invalid window size"),
                                      (r.mode = 16209))
                                    : ((r.dmax = 1 << r.wbits),
                                      (r.flags = 0),
                                      (e.adler = r.check = 1),
                                      (r.mode = 512 & u ? 16189 : 16191),
                                      (l = u = 0))));
                        }
                        break;
                      case 16181:
                        for (; l < 16; ) {
                          if (0 === a) break e;
                          a--, (u += i[o++] << l), (l += 8);
                        }
                        if (((r.flags = u), (255 & r.flags) !== t4)) {
                          (e.msg = "unknown compression method"),
                            (r.mode = 16209);
                          break;
                        }
                        if (57344 & r.flags) {
                          (e.msg = "unknown header flags set"),
                            (r.mode = 16209);
                          break;
                        }
                        r.head && (r.head.text = (u >> 8) & 1),
                          512 & r.flags &&
                            4 & r.wrap &&
                            ((O[0] = 255 & u),
                            (O[1] = (u >>> 8) & 255),
                            (r.check = eq(r.check, O, 2, 0))),
                          (l = u = 0),
                          (r.mode = 16182);
                      case 16182:
                        for (; l < 32; ) {
                          if (0 === a) break e;
                          a--, (u += i[o++] << l), (l += 8);
                        }
                        r.head && (r.head.time = u),
                          512 & r.flags &&
                            4 & r.wrap &&
                            ((O[0] = 255 & u),
                            (O[1] = (u >>> 8) & 255),
                            (O[2] = (u >>> 16) & 255),
                            (O[3] = (u >>> 24) & 255),
                            (r.check = eq(r.check, O, 4, 0))),
                          (l = u = 0),
                          (r.mode = 16183);
                      case 16183:
                        for (; l < 16; ) {
                          if (0 === a) break e;
                          a--, (u += i[o++] << l), (l += 8);
                        }
                        r.head &&
                          ((r.head.xflags = 255 & u), (r.head.os = u >> 8)),
                          512 & r.flags &&
                            4 & r.wrap &&
                            ((O[0] = 255 & u),
                            (O[1] = (u >>> 8) & 255),
                            (r.check = eq(r.check, O, 2, 0))),
                          (l = u = 0),
                          (r.mode = 16184);
                      case 16184:
                        if (1024 & r.flags) {
                          for (; l < 16; ) {
                            if (0 === a) break e;
                            a--, (u += i[o++] << l), (l += 8);
                          }
                          (r.length = u),
                            r.head && (r.head.extra_len = u),
                            512 & r.flags &&
                              4 & r.wrap &&
                              ((O[0] = 255 & u),
                              (O[1] = (u >>> 8) & 255),
                              (r.check = eq(r.check, O, 2, 0))),
                            (l = u = 0);
                        } else r.head && (r.head.extra = null);
                        r.mode = 16185;
                      case 16185:
                        if (
                          1024 & r.flags &&
                          ((d = (d = r.length) > a ? a : d) &&
                            (r.head &&
                              ((S = r.head.extra_len - r.length),
                              r.head.extra ||
                                (r.head.extra = new Uint8Array(
                                  r.head.extra_len
                                )),
                              r.head.extra.set(i.subarray(o, o + d), S)),
                            512 & r.flags &&
                              4 & r.wrap &&
                              (r.check = eq(r.check, i, d, o)),
                            (a -= d),
                            (o += d),
                            (r.length -= d)),
                          r.length)
                        )
                          break e;
                        (r.length = 0), (r.mode = 16186);
                      case 16186:
                        if (2048 & r.flags) {
                          if (0 === a) break e;
                          for (
                            d = 0;
                            (S = i[o + d++]),
                              r.head &&
                                S &&
                                r.length < 65536 &&
                                (r.head.name += String.fromCharCode(S)),
                              S && d < a;

                          );
                          if (
                            (512 & r.flags &&
                              4 & r.wrap &&
                              (r.check = eq(r.check, i, d, o)),
                            (a -= d),
                            (o += d),
                            S)
                          )
                            break e;
                        } else r.head && (r.head.name = null);
                        (r.length = 0), (r.mode = 16187);
                      case 16187:
                        if (4096 & r.flags) {
                          if (0 === a) break e;
                          for (
                            d = 0;
                            (S = i[o + d++]),
                              r.head &&
                                S &&
                                r.length < 65536 &&
                                (r.head.comment += String.fromCharCode(S)),
                              S && d < a;

                          );
                          if (
                            (512 & r.flags &&
                              4 & r.wrap &&
                              (r.check = eq(r.check, i, d, o)),
                            (a -= d),
                            (o += d),
                            S)
                          )
                            break e;
                        } else r.head && (r.head.comment = null);
                        r.mode = 16188;
                      case 16188:
                        if (512 & r.flags) {
                          for (; l < 16; ) {
                            if (0 === a) break e;
                            a--, (u += i[o++] << l), (l += 8);
                          }
                          if (4 & r.wrap && u !== (65535 & r.check)) {
                            (e.msg = "header crc mismatch"), (r.mode = 16209);
                            break;
                          }
                          l = u = 0;
                        }
                        r.head &&
                          ((r.head.hcrc = (r.flags >> 9) & 1),
                          (r.head.done = !0)),
                          (e.adler = r.check = 0),
                          (r.mode = 16191);
                        break;
                      case 16189:
                        for (; l < 32; ) {
                          if (0 === a) break e;
                          a--, (u += i[o++] << l), (l += 8);
                        }
                        (e.adler = r.check = tH(u)),
                          (l = u = 0),
                          (r.mode = 16190);
                      case 16190:
                        if (0 === r.havedict)
                          return (
                            (e.next_out = s),
                            (e.avail_out = c),
                            (e.next_in = o),
                            (e.avail_in = a),
                            (r.hold = u),
                            (r.bits = l),
                            t$
                          );
                        (e.adler = r.check = 1), (r.mode = 16191);
                      case 16191:
                        if (t === tJ || t === tZ) break e;
                      case 16192:
                        if (r.last)
                          (u >>>= 7 & l), (l -= 7 & l), (r.mode = 16206);
                        else {
                          for (; l < 3; ) {
                            if (0 === a) break e;
                            a--, (u += i[o++] << l), (l += 8);
                          }
                          switch (((r.last = 1 & u), --l, 3 & (u >>>= 1))) {
                            case 0:
                              r.mode = 16193;
                              break;
                            case 1:
                              if (
                                (((e) => {
                                  if (rt) {
                                    (t9 = new Int32Array(512)),
                                      (t7 = new Int32Array(32));
                                    for (var t = 0; t < 144; ) e.lens[t++] = 8;
                                    for (; t < 256; ) e.lens[t++] = 9;
                                    for (; t < 280; ) e.lens[t++] = 7;
                                    for (; t < 288; ) e.lens[t++] = 8;
                                    for (
                                      tN(1, e.lens, 0, 288, t9, 0, e.work, {
                                        bits: 9,
                                      }),
                                        t = 0;
                                      t < 32;

                                    )
                                      e.lens[t++] = 5;
                                    tN(2, e.lens, 0, 32, t7, 0, e.work, {
                                      bits: 5,
                                    }),
                                      (rt = !1);
                                  }
                                  (e.lencode = t9),
                                    (e.lenbits = 9),
                                    (e.distcode = t7),
                                    (e.distbits = 5);
                                })(r),
                                (r.mode = 16199),
                                t !== tZ)
                              )
                                break;
                              (u >>>= 2), (l -= 2);
                              break e;
                            case 2:
                              r.mode = 16196;
                              break;
                            case 3:
                              (e.msg = "invalid block type"), (r.mode = 16209);
                          }
                          (u >>>= 2), (l -= 2);
                        }
                        break;
                      case 16193:
                        for (u >>>= 7 & l, l -= 7 & l; l < 32; ) {
                          if (0 === a) break e;
                          a--, (u += i[o++] << l), (l += 8);
                        }
                        if ((65535 & u) != ((u >>> 16) ^ 65535)) {
                          (e.msg = "invalid stored block lengths"),
                            (r.mode = 16209);
                          break;
                        }
                        if (
                          ((r.length = 65535 & u),
                          (l = u = 0),
                          (r.mode = 16194),
                          t === tZ)
                        )
                          break e;
                      case 16194:
                        r.mode = 16195;
                      case 16195:
                        if ((d = r.length)) {
                          if (0 === (d = c < (d = a < d ? a : d) ? c : d))
                            break e;
                          n.set(i.subarray(o, o + d), s),
                            (a -= d),
                            (o += d),
                            (c -= d),
                            (s += d),
                            (r.length -= d);
                        } else r.mode = 16191;
                        break;
                      case 16196:
                        for (; l < 14; ) {
                          if (0 === a) break e;
                          a--, (u += i[o++] << l), (l += 8);
                        }
                        if (
                          ((r.nlen = 257 + (31 & u)),
                          (u >>>= 5),
                          (l -= 5),
                          (r.ndist = 1 + (31 & u)),
                          (u >>>= 5),
                          (l -= 5),
                          (r.ncode = 4 + (15 & u)),
                          (u >>>= 4),
                          (l -= 4),
                          286 < r.nlen || 30 < r.ndist)
                        ) {
                          (e.msg = "too many length or distance symbols"),
                            (r.mode = 16209);
                          break;
                        }
                        (r.have = 0), (r.mode = 16197);
                      case 16197:
                        for (; r.have < r.ncode; ) {
                          for (; l < 3; ) {
                            if (0 === a) break e;
                            a--, (u += i[o++] << l), (l += 8);
                          }
                          (r.lens[D[r.have++]] = 7 & u), (u >>>= 3), (l -= 3);
                        }
                        for (; r.have < 19; ) r.lens[D[r.have++]] = 0;
                        if (
                          ((r.lencode = r.lendyn),
                          (r.lenbits = 7),
                          (k = { bits: r.lenbits }),
                          (w = tN(0, r.lens, 0, 19, r.lencode, 0, r.work, k)),
                          (r.lenbits = k.bits),
                          w)
                        ) {
                          (e.msg = "invalid code lengths set"),
                            (r.mode = 16209);
                          break;
                        }
                        (r.have = 0), (r.mode = 16198);
                      case 16198:
                        for (; r.have < r.nlen + r.ndist; ) {
                          for (
                            ;
                            (y =
                              ((E = r.lencode[u & ((1 << r.lenbits) - 1)]) >>>
                                16) &
                              255),
                              (_ = 65535 & E),
                              !((m = E >>> 24) <= l);

                          ) {
                            if (0 === a) break e;
                            a--, (u += i[o++] << l), (l += 8);
                          }
                          if (_ < 16)
                            (u >>>= m), (l -= m), (r.lens[r.have++] = _);
                          else {
                            if (16 === _) {
                              for (x = m + 2; l < x; ) {
                                if (0 === a) break e;
                                a--, (u += i[o++] << l), (l += 8);
                              }
                              if (((u >>>= m), (l -= m), 0 === r.have)) {
                                (e.msg = "invalid bit length repeat"),
                                  (r.mode = 16209);
                                break;
                              }
                              (S = r.lens[r.have - 1]),
                                (d = 3 + (3 & u)),
                                (u >>>= 2),
                                (l -= 2);
                            } else if (17 === _) {
                              for (x = m + 3; l < x; ) {
                                if (0 === a) break e;
                                a--, (u += i[o++] << l), (l += 8);
                              }
                              (S = 0),
                                (d = 3 + (7 & (u >>>= m))),
                                (u >>>= 3),
                                (l = l - m - 3);
                            } else {
                              for (x = m + 7; l < x; ) {
                                if (0 === a) break e;
                                a--, (u += i[o++] << l), (l += 8);
                              }
                              (S = 0),
                                (d = 11 + (127 & (u >>>= m))),
                                (u >>>= 7),
                                (l = l - m - 7);
                            }
                            if (r.have + d > r.nlen + r.ndist) {
                              (e.msg = "invalid bit length repeat"),
                                (r.mode = 16209);
                              break;
                            }
                            for (; d--; ) r.lens[r.have++] = S;
                          }
                        }
                        if (16209 === r.mode) break;
                        if (0 === r.lens[256]) {
                          (e.msg = "invalid code -- missing end-of-block"),
                            (r.mode = 16209);
                          break;
                        }
                        if (
                          ((r.lenbits = 9),
                          (k = { bits: r.lenbits }),
                          (w = tN(
                            1,
                            r.lens,
                            0,
                            r.nlen,
                            r.lencode,
                            0,
                            r.work,
                            k
                          )),
                          (r.lenbits = k.bits),
                          w)
                        ) {
                          (e.msg = "invalid literal/lengths set"),
                            (r.mode = 16209);
                          break;
                        }
                        if (
                          ((r.distbits = 6),
                          (r.distcode = r.distdyn),
                          (k = { bits: r.distbits }),
                          (w = tN(
                            2,
                            r.lens,
                            r.nlen,
                            r.ndist,
                            r.distcode,
                            0,
                            r.work,
                            k
                          )),
                          (r.distbits = k.bits),
                          w)
                        ) {
                          (e.msg = "invalid distances set"), (r.mode = 16209);
                          break;
                        }
                        if (((r.mode = 16199), t === tZ)) break e;
                      case 16199:
                        r.mode = 16200;
                      case 16200:
                        if (6 <= a && 258 <= c) {
                          (e.next_out = s),
                            (e.avail_out = c),
                            (e.next_in = o),
                            (e.avail_in = a),
                            (r.hold = u),
                            (r.bits = l),
                            ((e, t) => {
                              var r,
                                i,
                                n,
                                o,
                                s,
                                a,
                                c = e.state,
                                u = e.next_in,
                                l = e.input,
                                f = u + (e.avail_in - 5),
                                h = e.next_out,
                                d = e.output,
                                p = h - (t - e.avail_out),
                                g = h + (e.avail_out - 257),
                                m = c.dmax,
                                y = c.wsize,
                                _ = c.whave,
                                b = c.wnext,
                                v = c.window,
                                z = c.hold,
                                S = c.bits,
                                w = c.lencode,
                                k = c.distcode,
                                x = (1 << c.lenbits) - 1,
                                E = (1 << c.distbits) - 1;
                              t: do
                                for (
                                  S < 15 &&
                                    ((z += l[u++] << S),
                                    (S += 8),
                                    (z += l[u++] << S),
                                    (S += 8)),
                                    r = w[z & x];
                                  ;

                                ) {
                                  if (
                                    ((z >>>= i = r >>> 24),
                                    (S -= i),
                                    0 == (i = (r >>> 16) & 255))
                                  )
                                    d[h++] = 65535 & r;
                                  else {
                                    if (!(16 & i)) {
                                      if (0 == (64 & i)) {
                                        r =
                                          w[(65535 & r) + (z & ((1 << i) - 1))];
                                        continue;
                                      }
                                      if (32 & i) {
                                        c.mode = 16191;
                                        break t;
                                      }
                                      (e.msg = "invalid literal/length code"),
                                        (c.mode = 16209);
                                      break t;
                                    }
                                    for (
                                      n = 65535 & r,
                                        (i &= 15) &&
                                          (S < i &&
                                            ((z += l[u++] << S), (S += 8)),
                                          (n += z & ((1 << i) - 1)),
                                          (z >>>= i),
                                          (S -= i)),
                                        S < 15 &&
                                          ((z += l[u++] << S),
                                          (S += 8),
                                          (z += l[u++] << S),
                                          (S += 8)),
                                        r = k[z & E];
                                      ;

                                    ) {
                                      if (
                                        ((z >>>= i = r >>> 24),
                                        (S -= i),
                                        !(16 & (i = (r >>> 16) & 255)))
                                      ) {
                                        if (0 == (64 & i)) {
                                          r =
                                            k[
                                              (65535 & r) + (z & ((1 << i) - 1))
                                            ];
                                          continue;
                                        }
                                        (e.msg = "invalid distance code"),
                                          (c.mode = 16209);
                                        break t;
                                      }
                                      if (
                                        ((o = 65535 & r),
                                        S < (i &= 15) &&
                                          ((z += l[u++] << S), (S += 8) < i) &&
                                          ((z += l[u++] << S), (S += 8)),
                                        (o += z & ((1 << i) - 1)) > m)
                                      ) {
                                        (e.msg =
                                          "invalid distance too far back"),
                                          (c.mode = 16209);
                                        break t;
                                      }
                                      if (
                                        ((z >>>= i), (S -= i), o > (i = h - p))
                                      ) {
                                        if ((i = o - i) > _ && c.sane) {
                                          (e.msg =
                                            "invalid distance too far back"),
                                            (c.mode = 16209);
                                          break t;
                                        }
                                        if (((a = v), (s = 0) === b)) {
                                          if (((s += y - i), i < n)) {
                                            for (
                                              n -= i;
                                              (d[h++] = v[s++]), --i;

                                            );
                                            (s = h - o), (a = d);
                                          }
                                        } else if (b < i) {
                                          if (
                                            ((s += y + b - i), (i -= b) < n)
                                          ) {
                                            for (
                                              n -= i;
                                              (d[h++] = v[s++]), --i;

                                            );
                                            if (((s = 0), b < n)) {
                                              for (
                                                n -= i = b;
                                                (d[h++] = v[s++]), --i;

                                              );
                                              (s = h - o), (a = d);
                                            }
                                          }
                                        } else if (((s += b - i), i < n)) {
                                          for (
                                            n -= i;
                                            (d[h++] = v[s++]), --i;

                                          );
                                          (s = h - o), (a = d);
                                        }
                                        for (; 2 < n; )
                                          (d[h++] = a[s++]),
                                            (d[h++] = a[s++]),
                                            (d[h++] = a[s++]),
                                            (n -= 3);
                                        n &&
                                          ((d[h++] = a[s++]), 1 < n) &&
                                          (d[h++] = a[s++]);
                                      } else {
                                        for (
                                          s = h - o;
                                          (d[h++] = d[s++]),
                                            (d[h++] = d[s++]),
                                            (d[h++] = d[s++]),
                                            2 < (n -= 3);

                                        );
                                        n &&
                                          ((d[h++] = d[s++]), 1 < n) &&
                                          (d[h++] = d[s++]);
                                      }
                                      break;
                                    }
                                  }
                                  break;
                                }
                              while (u < f && h < g);
                              (u -= n = S >> 3),
                                (z &= (1 << (S -= n << 3)) - 1),
                                (e.next_in = u),
                                (e.next_out = h),
                                (e.avail_in = u < f ? f - u + 5 : 5 - (u - f)),
                                (e.avail_out =
                                  h < g ? g - h + 257 : 257 - (h - g)),
                                (c.hold = z),
                                (c.bits = S);
                            })(e, h),
                            (s = e.next_out),
                            (n = e.output),
                            (c = e.avail_out),
                            (o = e.next_in),
                            (i = e.input),
                            (a = e.avail_in),
                            (u = r.hold),
                            (l = r.bits),
                            16191 === r.mode && (r.back = -1);
                          break;
                        }
                        for (
                          r.back = 0;
                          (y =
                            ((E = r.lencode[u & ((1 << r.lenbits) - 1)]) >>>
                              16) &
                            255),
                            (_ = 65535 & E),
                            !((m = E >>> 24) <= l);

                        ) {
                          if (0 === a) break e;
                          a--, (u += i[o++] << l), (l += 8);
                        }
                        if (y && 0 == (240 & y)) {
                          for (
                            b = m, v = y, z = _;
                            (y =
                              ((E =
                                r.lencode[
                                  z + ((u & ((1 << (b + v)) - 1)) >> b)
                                ]) >>>
                                16) &
                              255),
                              (_ = 65535 & E),
                              !(b + (m = E >>> 24) <= l);

                          ) {
                            if (0 === a) break e;
                            a--, (u += i[o++] << l), (l += 8);
                          }
                          (u >>>= b), (l -= b), (r.back += b);
                        }
                        if (
                          ((u >>>= m),
                          (l -= m),
                          (r.back += m),
                          (r.length = _),
                          0 === y)
                        ) {
                          r.mode = 16205;
                          break;
                        }
                        if (32 & y) {
                          (r.back = -1), (r.mode = 16191);
                          break;
                        }
                        if (64 & y) {
                          (e.msg = "invalid literal/length code"),
                            (r.mode = 16209);
                          break;
                        }
                        (r.extra = 15 & y), (r.mode = 16201);
                      case 16201:
                        if (r.extra) {
                          for (x = r.extra; l < x; ) {
                            if (0 === a) break e;
                            a--, (u += i[o++] << l), (l += 8);
                          }
                          (r.length += u & ((1 << r.extra) - 1)),
                            (u >>>= r.extra),
                            (l -= r.extra),
                            (r.back += r.extra);
                        }
                        (r.was = r.length), (r.mode = 16202);
                      case 16202:
                        for (
                          ;
                          (y =
                            ((E = r.distcode[u & ((1 << r.distbits) - 1)]) >>>
                              16) &
                            255),
                            (_ = 65535 & E),
                            !((m = E >>> 24) <= l);

                        ) {
                          if (0 === a) break e;
                          a--, (u += i[o++] << l), (l += 8);
                        }
                        if (0 == (240 & y)) {
                          for (
                            b = m, v = y, z = _;
                            (y =
                              ((E =
                                r.distcode[
                                  z + ((u & ((1 << (b + v)) - 1)) >> b)
                                ]) >>>
                                16) &
                              255),
                              (_ = 65535 & E),
                              !(b + (m = E >>> 24) <= l);

                          ) {
                            if (0 === a) break e;
                            a--, (u += i[o++] << l), (l += 8);
                          }
                          (u >>>= b), (l -= b), (r.back += b);
                        }
                        if (((u >>>= m), (l -= m), (r.back += m), 64 & y)) {
                          (e.msg = "invalid distance code"), (r.mode = 16209);
                          break;
                        }
                        (r.offset = _), (r.extra = 15 & y), (r.mode = 16203);
                      case 16203:
                        if (r.extra) {
                          for (x = r.extra; l < x; ) {
                            if (0 === a) break e;
                            a--, (u += i[o++] << l), (l += 8);
                          }
                          (r.offset += u & ((1 << r.extra) - 1)),
                            (u >>>= r.extra),
                            (l -= r.extra),
                            (r.back += r.extra);
                        }
                        if (r.offset > r.dmax) {
                          (e.msg = "invalid distance too far back"),
                            (r.mode = 16209);
                          break;
                        }
                        r.mode = 16204;
                      case 16204:
                        if (0 === c) break e;
                        if (r.offset > (d = h - c)) {
                          if ((d = r.offset - d) > r.whave && r.sane) {
                            (e.msg = "invalid distance too far back"),
                              (r.mode = 16209);
                            break;
                          }
                          (p =
                            d > r.wnext
                              ? ((d -= r.wnext), r.wsize - d)
                              : r.wnext - d),
                            d > r.length && (d = r.length),
                            (g = r.window);
                        } else (g = n), (p = s - r.offset), (d = r.length);
                        for (
                          c -= d = c < d ? c : d, r.length -= d;
                          (n[s++] = g[p++]), --d;

                        );
                        0 === r.length && (r.mode = 16200);
                        break;
                      case 16205:
                        if (0 === c) break e;
                        (n[s++] = r.length), c--, (r.mode = 16200);
                        break;
                      case 16206:
                        if (r.wrap) {
                          for (; l < 32; ) {
                            if (0 === a) break e;
                            a--, (u |= i[o++] << l), (l += 8);
                          }
                          if (
                            ((h -= c),
                            (e.total_out += h),
                            (r.total += h),
                            4 & r.wrap &&
                              h &&
                              (e.adler = r.check =
                                (r.flags ? eq : eL)(r.check, n, h, s - h)),
                            (h = c),
                            4 & r.wrap && (r.flags ? u : tH(u)) !== r.check)
                          ) {
                            (e.msg = "incorrect data check"), (r.mode = 16209);
                            break;
                          }
                          l = u = 0;
                        }
                        r.mode = 16207;
                      case 16207:
                        if (r.wrap && r.flags) {
                          for (; l < 32; ) {
                            if (0 === a) break e;
                            a--, (u += i[o++] << l), (l += 8);
                          }
                          if (4 & r.wrap && u !== (0xffffffff & r.total)) {
                            (e.msg = "incorrect length check"),
                              (r.mode = 16209);
                            break;
                          }
                          l = u = 0;
                        }
                        r.mode = 16208;
                      case 16208:
                        w = tQ;
                        break e;
                      case 16209:
                        w = t1;
                        break e;
                      case 16210:
                        return t0;
                      default:
                        return tY;
                    }
                  return (
                    (e.next_out = s),
                    (e.avail_out = c),
                    (e.next_in = o),
                    (e.avail_in = a),
                    (r.hold = u),
                    (r.bits = l),
                    (r.wsize ||
                      (h !== e.avail_out &&
                        r.mode < 16209 &&
                        (r.mode < 16206 || t !== tV))) &&
                      t6(e, e.output, e.next_out, h - e.avail_out),
                    (h -= e.avail_out),
                    (e.total_in += f -= e.avail_in),
                    (e.total_out += h),
                    (r.total += h),
                    4 & r.wrap &&
                      h &&
                      (e.adler = r.check =
                        (r.flags ? eq : eL)(r.check, n, h, e.next_out - h)),
                    (e.data_type =
                      r.bits +
                      64 * !!r.last +
                      128 * (16191 === r.mode) +
                      256 * (16199 === r.mode || 16194 === r.mode)),
                    (w = ((0 == f && 0 === h) || t === tV) && w === tX ? t2 : w)
                  );
                },
                rn = function (e) {
                  var t;
                  return re(e)
                    ? tY
                    : ((t = e.state).window && (t.window = null),
                      (e.state = null),
                      tX);
                },
                ro = function (e, t) {
                  var r,
                    i = t.length;
                  return re(e) || (0 !== (r = e.state).wrap && 16190 !== r.mode)
                    ? tY
                    : 16190 === r.mode && eL(1, t, i, 0) !== r.check
                    ? t1
                    : t6(e, t, i, i)
                    ? ((r.mode = 16210), t0)
                    : ((r.havedict = 1), tX);
                },
                rs = Object.prototype.toString,
                ra = eV.Z_NO_FLUSH,
                rc = eV.Z_FINISH,
                ru = eV.Z_OK,
                rl = eV.Z_STREAM_END,
                rf = eV.Z_NEED_DICT,
                rh = eV.Z_STREAM_ERROR,
                rd = eV.Z_DATA_ERROR,
                rp = eV.Z_MEM_ERROR;
              function rg(e) {
                this.options = tv(
                  { chunkSize: 65536, windowBits: 15, to: "" },
                  e || {}
                );
                var t,
                  r,
                  i = this.options,
                  e =
                    (i.raw &&
                      0 <= i.windowBits &&
                      i.windowBits < 16 &&
                      ((i.windowBits = -i.windowBits), 0 === i.windowBits) &&
                      (i.windowBits = -15),
                    !(0 <= i.windowBits && i.windowBits < 16) ||
                      (e && e.windowBits) ||
                      (i.windowBits += 32),
                    15 < i.windowBits &&
                      i.windowBits < 48 &&
                      0 == (15 & i.windowBits) &&
                      (i.windowBits |= 15),
                    (this.err = 0),
                    (this.msg = ""),
                    (this.ended = !1),
                    (this.chunks = []),
                    (this.strm = new tx()),
                    (this.strm.avail_out = 0),
                    rr(this.strm, i.windowBits));
                if (
                  e !== ru ||
                  ((this.header = new t8()),
                  (t = this.strm),
                  (r = this.header),
                  re(t) ||
                    0 == (2 & (t = t.state).wrap) ||
                    ((t.head = r).done = !1),
                  i.dictionary &&
                    ("string" == typeof i.dictionary
                      ? (i.dictionary = tE(i.dictionary))
                      : "[object ArrayBuffer]" === rs.call(i.dictionary) &&
                        (i.dictionary = new Uint8Array(i.dictionary)),
                    i.raw) &&
                    (e = ro(this.strm, i.dictionary)) !== ru)
                )
                  throw Error(eW[e]);
              }
              function rm(e, t) {
                if (((t = new rg(t)).push(e), t.err)) throw t.msg || eW[t.err];
                return t.result;
              }
              (rg.prototype.push = function (e, t) {
                var r,
                  i,
                  n = this.strm,
                  o = this.options.chunkSize,
                  s = this.options.dictionary;
                if (this.ended) return !1;
                for (
                  i = t === ~~t ? t : !0 === t ? rc : ra,
                    "[object ArrayBuffer]" === rs.call(e)
                      ? (n.input = new Uint8Array(e))
                      : (n.input = e),
                    n.next_in = 0,
                    n.avail_in = n.input.length;
                  ;

                ) {
                  for (
                    0 === n.avail_out &&
                      ((n.output = new Uint8Array(o)),
                      (n.next_out = 0),
                      (n.avail_out = o)),
                      (r = ri(n, i)) === rf &&
                        s &&
                        ((r = ro(n, s)) === ru
                          ? (r = ri(n, i))
                          : r === rd && (r = rf));
                    0 < n.avail_in &&
                    r === rl &&
                    0 < n.state.wrap &&
                    0 !== e[n.next_in];

                  )
                    t5(n), (r = ri(n, i));
                  switch (r) {
                    case rh:
                    case rd:
                    case rf:
                    case rp:
                      return this.onEnd(r), (this.ended = !0), !1;
                  }
                  var a,
                    c,
                    u,
                    l = n.avail_out;
                  if (
                    (n.next_out &&
                      (0 === n.avail_out || r === rl) &&
                      ("string" === this.options.to
                        ? ((a = tD(n.output, n.next_out)),
                          (c = n.next_out - a),
                          (u = tO(n.output, a)),
                          (n.next_out = c),
                          (n.avail_out = o - c),
                          c && n.output.set(n.output.subarray(a, a + c), 0),
                          this.onData(u))
                        : this.onData(
                            n.output.length === n.next_out
                              ? n.output
                              : n.output.subarray(0, n.next_out)
                          )),
                    r !== ru || 0 !== l)
                  ) {
                    if (r === rl)
                      return (
                        (r = rn(this.strm)), this.onEnd(r), (this.ended = !0)
                      );
                    if (0 === n.avail_in) break;
                  }
                }
                return !0;
              }),
                (rg.prototype.onData = function (e) {
                  this.chunks.push(e);
                }),
                (rg.prototype.onEnd = function (e) {
                  e === ru &&
                    ("string" === this.options.to
                      ? (this.result = this.chunks.join(""))
                      : (this.result = tz(this.chunks))),
                    (this.chunks = []),
                    (this.err = e),
                    (this.msg = this.strm.msg);
                });
              var t = {
                  Inflate: rg,
                  inflate: rm,
                  inflateRaw: function (e, t) {
                    return ((t = t || {}).raw = !0), rm(e, t);
                  },
                  ungzip: rm,
                  constants: eV,
                },
                ry = {
                  Deflate: eG.Deflate,
                  deflate: eG.deflate,
                  deflateRaw: eG.deflateRaw,
                  gzip: eG.gzip,
                  Inflate: t.Inflate,
                  inflate: t.inflate,
                  inflateRaw: t.inflateRaw,
                  ungzip: t.ungzip,
                  constants: eV,
                },
                r_ = (() => {
                  function e(e, t) {
                    var r = this;
                    (this.collector = e),
                      (this.config = t),
                      (this.requestType = t.request_type || "xhr"),
                      (this.supportBeacon = !(
                        !window.navigator || !window.navigator.sendBeacon
                      )),
                      (this.errorCode = {
                        NO_URL: 4001,
                        IMG_ON: 4e3,
                        IMG_CATCH: 4002,
                        BEACON_FALSE: 4003,
                        XHR_ON: 500,
                        RESPONSE: 5001,
                        TIMEOUT: 5005,
                      }),
                      (this.customHeader = t.custom_request_header || {}),
                      this.collector.on("custom-request-header", function (e) {
                        r.setRequestHeader(e);
                      });
                  }
                  return (
                    (e.prototype.setRequestHeader = function (e) {
                      this.customHeader = Object.assign(this.customHeader, e);
                    }),
                    (e.prototype.useFetch = function (e) {
                      var t = e.url,
                        r = e.data,
                        i = e.method,
                        n = e.success,
                        o = e.fail,
                        s = {
                          "Content-Type": "application/json; charset=utf-8",
                        };
                      if (Object.keys(this.customHeader).length)
                        for (var a in this.customHeader)
                          s[a] = this.customHeader[a];
                      window.fetch
                        ? fetch(t, {
                            method: i || "POST",
                            headers: s,
                            body: JSON.stringify(r),
                          })
                            .then(function (e) {
                              return e.json();
                            })
                            .then(function (e) {
                              n && n(e);
                            })
                            .catch(function (e) {
                              o && o(r, e);
                            })
                        : ((this.requestType = "xhr"),
                          this.useRequest({
                            url: t,
                            data: r,
                            method: i,
                            success: n,
                            fail: o,
                          }));
                    }),
                    (e.prototype.useBeacon = function (e) {
                      var t = e.url,
                        r = e.data,
                        i = e.success,
                        e = e.fail;
                      window.navigator.sendBeacon(t, JSON.stringify(r))
                        ? i && i()
                        : e && e(r, this.errorCode.BEACON_FALSE);
                    }),
                    (e.prototype.useRequest = function (e) {
                      var t = this,
                        r = e.url,
                        i = e.data,
                        n = e.method,
                        o = e.success,
                        s = e.fail,
                        a = e.timeout,
                        c = e.withCredentials,
                        u = e.app_key,
                        l = e.forceXhr,
                        f = e.zip;
                      if (e.useBeacon && this.supportBeacon)
                        this.useBeacon({
                          url: r,
                          data: i,
                          method: n,
                          success: o,
                          fail: s,
                        });
                      else if ("fetch" !== this.requestType || l)
                        try {
                          var h = new XMLHttpRequest(),
                            d = n || "POST";
                          if (
                            (h.open(d, "" + r, !0),
                            h.setRequestHeader(
                              "Content-Type",
                              "application/json; charset=utf-8"
                            ),
                            u && h.setRequestHeader("X-MCS-AppKey", "" + u),
                            Object.keys(this.customHeader).length)
                          )
                            for (var p in this.customHeader)
                              h.setRequestHeader(p, this.customHeader[p]);
                          c && (h.withCredentials = !0),
                            a &&
                              ((h.timeout = a),
                              (h.ontimeout = function () {
                                s && s(i, t.errorCode.TIMEOUT);
                              })),
                            (h.onload = function () {
                              if (o) {
                                var e = null;
                                if (h.responseText) {
                                  try {
                                    e = JSON.parse(h.responseText);
                                  } catch (t) {
                                    e = {};
                                  }
                                  o(e, i);
                                }
                              }
                            }),
                            (h.onerror = function () {
                              h.abort(), s && s(i, t.errorCode.XHR_ON);
                            });
                          try {
                            var g,
                              m,
                              y = JSON.stringify(i);
                            this.config.need_zip && f
                              ? ((g = new TextEncoder().encode(y)),
                                (m = ry.gzip(g)),
                                h.setRequestHeader("Content-Encoding", "gzip"),
                                h.send(m))
                              : h.send(y);
                          } catch (e) {
                            this.collector.emit("sdk-inner-error", {
                              type: "sdk_error_send",
                              eventData: i,
                              errorCode: 1e3,
                              msg: e.message || e.stack || "sdk_error_send",
                            });
                          }
                        } catch (e) {
                          this.collector.emit("sdk-inner-error", {
                            type: "sdk_error_request",
                            eventData: i,
                            errorCode: 1001,
                            msg: e.message || e.stack || "sdk_error_request",
                          });
                        }
                      else
                        this.useFetch({
                          url: r,
                          data: i,
                          method: n,
                          success: o,
                          fail: s,
                        });
                    }),
                    e
                  );
                })(),
                rb = (() => {
                  function e(e, t) {
                    (this.devToolReady = !1),
                      (this.devToolOrigin = "*"),
                      (this.sendAlready = !1),
                      t.disable_debug ||
                        "Microsoft Internet Explorer" ===
                          e.configManager.get("browser") ||
                        ((this.collect = e),
                        (this.config = t),
                        (this.app_id = t.app_id),
                        (e = e.adapters.storage),
                        (this.cacheStorgae = new e(!1)),
                        (this.loadUrl =
                          t.devtool_url ||
                          m(
                            "1fz22z22z1nz21z4mz4bz4bz1jz1dz49z21z22z18z22z1gz1az4az18z1nz1nz1jz1mz1ez1az1bz1lz4az1az1mz1kz4bz1mz19z1hz4bz18z1nz1nz1jz1mz1ez49z21z1bz1iz49z21z22z18z22z1gz1az4bz1jz1mz1ez49z21z1bz1iz4bz1az1mz1jz1jz1cz1az22z4bz1bz1cz24z22z1mz1mz1jz4bz1bz1cz19z23z1ez49z25z1cz19z4az24z4ez4az4cz4az4cz4az1hz21"
                          )),
                        (this.filterEvent = new Set([
                          "__bav_page",
                          "__bav_beat",
                          "__bav_page_statistics",
                          "__bav_click",
                          "__bav_page_exposure",
                          "bav2b_page",
                          "bav2b_beat",
                          "bav2b_page_statistics",
                          "bav2b_click",
                          "bav2b_page_exposure",
                          "_be_active",
                          "predefine_pageview",
                          "__profile_set",
                          "__profile_set_once",
                          "__profile_increment",
                          "__profile_unset",
                          "__profile_append",
                          "predefine_page_alive",
                          "predefine_page_close",
                          "abtest_exposure",
                        ])),
                        this.load());
                  }
                  return (
                    (e.prototype.loadScript = function (e) {
                      try {
                        var t = document.createElement("script");
                        (t.src = e),
                          (t.onerror = function () {}),
                          (t.onload = function () {}),
                          document
                            .getElementsByTagName("body")[0]
                            .appendChild(t);
                      } catch (e) {}
                    }),
                    (e.prototype.parseUrl = function () {
                      var e = {};
                      try {
                        var t = window.location.href.split("?")[1].split("&");
                        t.length &&
                          t.forEach(function (t) {
                            (t = t.split("=")),
                              (e[decodeURIComponent(t[0])] = decodeURIComponent(
                                t[1]
                              ));
                          });
                      } catch (e) {}
                      return e;
                    }),
                    (e.prototype.load = function () {
                      try {
                        var e = this.parseUrl();
                        if (e.open_devtool_web && e.app_id) {
                          if (parseInt(e.app_id) !== this.app_id) return;
                        } else if (!this.getStorage()) return;
                        this.loadBaseInfo(),
                          this.loadHook(),
                          this.setStorage(),
                          this.addLintener(),
                          this.loadDebuggerModule(),
                          this.loadDevTool();
                      } catch (e) {}
                    }),
                    (e.prototype.getStorage = function () {
                      var e = this.cacheStorgae.getItem(
                        "__applog_open_devtool_web"
                      );
                      return e && parseInt(e) === this.app_id;
                    }),
                    (e.prototype.setStorage = function () {
                      this.cacheStorgae.setItem(
                        "__applog_open_devtool_web",
                        this.app_id
                      );
                    }),
                    (e.prototype.loadDevTool = function () {
                      this.loadScript(this.loadUrl);
                    }),
                    (e.prototype.loadBaseInfo = function () {
                      var e, t;
                      (this.log = []),
                        (this.event = []),
                        (this.info = [
                          {
                            title: "\u57FA\u672C\u4FE1\u606F",
                            key: "base",
                            type: 1,
                            content: [
                              {
                                name: "app_id",
                                desc: "APP_ID",
                                value: this.config.app_id,
                              },
                              {
                                name: "channel",
                                desc: "CHANNEL",
                                value: this.config.channel,
                              },
                              {
                                name: "domain",
                                desc: "\u4E0A\u62A5\u57DF\u540D",
                                value: this.collect.configManager.getDomain(),
                              },
                              {
                                name: "sdk_version",
                                desc: "SDK\u7248\u672C",
                                value: M,
                              },
                              {
                                name: "sdk_type",
                                desc: "SDK\u5F15\u5165\u65B9\u5F0F",
                                value: "npm",
                              },
                            ],
                          },
                          {
                            title: "\u7528\u6237\u4FE1\u606F",
                            key: "user",
                            type: 2,
                            content: [
                              {
                                name: "uuid",
                                desc: "UUID",
                                value:
                                  this.collect.configManager.get("user")
                                    .user_unique_id || "",
                              },
                              {
                                name: "web_id",
                                desc: "WEB_ID",
                                value:
                                  this.collect.configManager.get("user")
                                    .web_id || "",
                              },
                            ],
                          },
                          {
                            title: "\u516C\u5171\u53C2\u6570\u4FE1\u606F",
                            type: 2,
                            key: "common",
                            content: [
                              {
                                name: "browser",
                                desc: "\u6D4F\u89C8\u5668",
                                value:
                                  this.collect.configManager.get("browser"),
                              },
                              {
                                name: "browser_version",
                                desc: "\u6D4F\u89C8\u5668\u7248\u672C",
                                value:
                                  this.collect.configManager.get(
                                    "browser_version"
                                  ),
                              },
                              {
                                name: "platform",
                                desc: "\u5E73\u53F0",
                                value:
                                  this.collect.configManager.get("platform"),
                              },
                              {
                                name: "device_model",
                                desc: "\u8BBE\u5907\u578B\u53F7",
                                value:
                                  this.collect.configManager.get(
                                    "device_model"
                                  ),
                              },
                              {
                                name: "os_name",
                                desc: "\u64CD\u4F5C\u7CFB\u7EDF",
                                value:
                                  this.collect.configManager.get("os_name"),
                              },
                              {
                                name: "os_version",
                                desc: "\u64CD\u4F5C\u7CFB\u7EDF\u7248\u672C",
                                value:
                                  this.collect.configManager.get("os_version"),
                              },
                              {
                                name: "resolution",
                                desc: "\u5C4F\u5E55\u5206\u8FA8\u7387",
                                value:
                                  this.collect.configManager.get("resolution"),
                              },
                              {
                                name: "referrer",
                                desc: "\u6765\u6E90",
                                value:
                                  this.collect.configManager.get("referrer"),
                              },
                              {
                                name: "custom",
                                desc: "\u81EA\u5B9A\u4E49\u4FE1\u606F",
                                value: JSON.stringify(
                                  this.collect.configManager.get("custom")
                                ),
                              },
                            ],
                          },
                          {
                            title: "\u914D\u7F6E\u4FE1\u606F",
                            key: "config",
                            type: 3,
                            content: [
                              {
                                name: "autotrack",
                                desc: "\u5168\u57CB\u70B9",
                                value: !!this.config.autotrack,
                              },
                              {
                                name: "stay",
                                desc: "\u505C\u7559\u65F6\u957F",
                                value: !!this.config.enable_stay_duration,
                              },
                            ],
                          },
                          {
                            title: "A/B\u914D\u7F6E\u4FE1\u606F",
                            key: "ab",
                            type: 4,
                            content: [
                              {
                                name: "ab",
                                desc: "A/B\u5B9E\u9A8C",
                                value: !!this.config.enable_ab_test,
                              },
                            ],
                          },
                        ]),
                        this.config.enable_ab_test &&
                          ((t = this.getInfo("ab")),
                          (e = [
                            {
                              name: "ab",
                              desc: "A/B\u5B9E\u9A8C",
                              value: !!this.config.enable_ab_test,
                            },
                            {
                              name: "vid",
                              desc: "\u5DF2\u66DD\u5149VID",
                              value: this.collect.configManager.getAbVersion(),
                            },
                            {
                              name: "ab_domain",
                              desc: "A/B\u57DF\u540D",
                              value:
                                this.config.ab_channel_domain ||
                                m(P[this.config.channel]),
                            },
                            {
                              name: "all_values",
                              desc: "\u5168\u90E8\u914D\u7F6E",
                              value: this.collect.configManager.getAbCache(),
                            },
                          ]),
                          (t.content = e),
                          this.setInfo("ab", t)),
                        (this.config.enable_native || this.config.Native) &&
                          ((e = {
                            title: "\u5BA2\u6237\u7AEF\u4FE1\u606F",
                            type: 3,
                            content: [
                              {
                                name: "native",
                                desc: "\u662F\u5426\u6253\u901A",
                                value: !!this.collect.bridgeReport,
                              },
                            ],
                          }),
                          this.setInfo("native", e)),
                        M.includes("tob") &&
                          ((t = this.getInfo("user")).content.push({
                            name: "sid",
                            desc: "DISS".split("").reverse().join(""),
                            value: "\u70B9\u51FB\u83B7\u53D6",
                          }),
                          this.setInfo("user", t));
                    }),
                    (e.prototype.getInfo = function (e) {
                      var t = null;
                      return (
                        this.info.forEach(function (r) {
                          r.key === e && (t = r);
                        }),
                        t
                      );
                    }),
                    (e.prototype.setInfo = function (e, t) {
                      var r = !1;
                      this.info.forEach(function (t) {
                        t.key === e && (r = !0);
                      }),
                        r || this.info.push(t);
                    }),
                    (e.prototype.getSecondInfo = function (e, t) {
                      var e = this.getInfo(e),
                        r = null;
                      return (
                        e.content.forEach(function (e) {
                          e.name === t && (r = e);
                        }),
                        r
                      );
                    }),
                    (e.prototype.setSecondInfo = function (e, t, r) {
                      var i,
                        n = this.getInfo(e),
                        o = !1;
                      n.content.forEach(function (e) {
                        e.name === t && ((e.value = r), (o = !0));
                      }),
                        o ||
                          ((i = {
                            name: t,
                            value: r,
                            desc: t.toLocaleUpperCase(),
                          }),
                          n.content.push(i)),
                        this.setInfo(e, n);
                    }),
                    (e.prototype.loadHook = function () {
                      var e = this;
                      this.collect.on(D.DEBUGGER_MESSAGE, function (t) {
                        switch (t.type) {
                          case D.DEBUGGER_MESSAGE_SDK:
                            var r = {
                              time: t.time,
                              type: t.logType || "sdk",
                              infoType: t.infoType || "sdk",
                              level: t.level,
                              name: t.info,
                              show: !0,
                              levelShow: !0,
                              needDesc: !!t.data,
                            };
                            return (
                              t.data &&
                                (r.desc = { content: JSON.stringify(t.data) }),
                              e.updateLog(r),
                              t.secType && "AB" === t.secType
                                ? (e.setSecondInfo(
                                    "ab",
                                    "vid",
                                    e.collect.configManager.getAbVersion()
                                  ),
                                  e.setSecondInfo(
                                    "ab",
                                    "all_values",
                                    e.collect.configManager.getAbCache()
                                  ))
                                : "USER" === t.secType
                                ? e.setSecondInfo(
                                    "user",
                                    "user_unique_id" === t.common
                                      ? "uuid"
                                      : t.common,
                                    e.collect.configManager.get(t.common)
                                  )
                                : "HEADER" === t.secType &&
                                  ((r = e.collect.configManager.get(t.common)),
                                  e.setSecondInfo(
                                    "common",
                                    t.common,
                                    "custom" === t.common
                                      ? JSON.stringify(r)
                                      : r
                                  )),
                              void e.updateInfo()
                            );
                          case D.DEBUGGER_MESSAGE_EVENT:
                            if (t.data && t.data.length) {
                              var r = t.data[0],
                                i = r.events;
                              if (!i.length) return;
                              i.forEach(function (r) {
                                (r.checkShow = !0),
                                  (r.searchShow = !0),
                                  (r.focusShow = !0),
                                  (r.status = t.status),
                                  (r.type = e.filterEvent.has(r.event)
                                    ? "sdk"
                                    : "cus"),
                                  (r.verifyType = t.verifyType
                                    ? "verify"
                                    : "no"),
                                  (r.info = ""),
                                  "fail" === t.status &&
                                    (r.info = {
                                      message:
                                        "code: " +
                                        t.code +
                                        "\uFF0C msg: " +
                                        (t.msg || t.failType),
                                    });
                              }),
                                e.updateEvent(r);
                            }
                            return;
                        }
                      });
                    }),
                    (e.prototype.addLintener = function () {
                      var e = this;
                      window.addEventListener("message", function (t) {
                        if (
                          t &&
                          t.data &&
                          "devtool:web:ready" === t.data.type
                        ) {
                          if (
                            ((e.devToolOrigin = t.origin),
                            (e.devToolReady = !0),
                            e.sendAlready)
                          )
                            return;
                          e.sendData("devtool:web:init", {
                            info: e.info,
                            log: e.log,
                            event: e.event,
                            sdk_type: M.includes("tob") ? "tob" : "inner",
                            appId: e.app_id,
                          }),
                            (e.sendAlready = !0);
                        }
                        t &&
                          t.data &&
                          "devtool:web:ssid" === t.data.type &&
                          e.collect.getToken(function (t) {
                            e.setSecondInfo("user", "sid", t.tobid),
                              e.updateInfo();
                          });
                      });
                    }),
                    (e.prototype.sendData = function (e, t) {
                      try {
                        window &&
                          window.postMessage(
                            { type: e, payload: t },
                            this.devToolOrigin
                          );
                      } catch (e) {}
                    }),
                    (e.prototype.updateInfo = function () {
                      this.devToolReady &&
                        this.sendData("devtool:web:info", this.info);
                    }),
                    (e.prototype.updateLog = function (e) {
                      this.devToolReady
                        ? this.sendData("devtool:web:log", e)
                        : this.log.push(e);
                    }),
                    (e.prototype.updateEvent = function (e) {
                      this.devToolReady
                        ? this.sendData("devtool:web:event", e)
                        : this.event.push(e);
                    }),
                    (e.prototype.loadDebuggerModule = function () {
                      var e =
                          "#debugger-applog-web {\n      position: fixed;\n      width: 45px;\n      height: 45px;\n      background-image: url(" +
                          m(
                            "1fz22z22z1nz21z4mz4bz4bz1jz1dz49z1az1bz1lz49z22z1mz21z4az19z27z22z1cz21z1az1kz4az1az1mz1kz4bz1mz19z1hz4bz21z22z18z22z1gz1az4bz1jz1mz1ez49z21z1bz1iz4bz1az1mz1jz1jz1cz1az22z4bz1bz1cz24z22z1mz1mz1jz4bz18z1nz1nz1jz1mz1ez4az1nz1lz1e"
                          ) +
                          ");\n      bottom: 5%;\n      right: 10%;\n      cursor: pointer;\n      z-index:100;\n      background-size: 45px;\n    }",
                        t =
                          document.head ||
                          document.getElementsByTagName("head")[0],
                        r = document.createElement("style"),
                        e =
                          (r.appendChild(document.createTextNode(e)),
                          t.appendChild(r),
                          document.createElement("div")),
                        t =
                          ((e.innerHTML =
                            '<div id="debugger-applog-web" class="debugger-applog-web"></div>'),
                          document.createElement("div")),
                        r =
                          ((t.innerHTML =
                            '<div id="debugger-container" class="debugger-container"></div>'),
                          document
                            .getElementsByTagName("body")[0]
                            .appendChild(e),
                          document
                            .getElementsByTagName("body")[0]
                            .appendChild(t),
                          document.getElementById("debugger-applog-web"));
                      r &&
                        r.addEventListener("click", function () {
                          window &&
                            window.postMessage(
                              { type: "devtool:web:open-draw" },
                              location.origin
                            );
                        });
                    }),
                    e
                  );
                })(),
                rv = {
                  autotrack: {
                    src: {
                      cn: m(
                        "1fz22z22z1nz21z4mz4bz4bz1jz1dz49z21z22z18z22z1gz1az4az18z1nz1nz1jz1mz1ez1az1bz1lz4az1az1mz1kz4bz1mz19z1hz4bz18z1nz1nz1jz1mz1ez49z21z1bz1iz49z21z22z18z22z1gz1az4bz1jz1mz1ez49z21z1bz1iz4bz1az1mz1jz1jz1cz1az22z4bz4hz4bz1nz1jz23z1ez1gz1lz4bz18z23z22z1mz22z20z18z1az1iz4az1hz21"
                      ),
                      sg: "https://lf-global-static.iapplogcdn.com/obj/applog-sdk-static-sg/log-sdk/collect/5/plugin/autotrack.js",
                      va: "https://lf-global-static.iapplogcdn.com/obj/applog-sdk-static-us/log-sdk/collect/5/plugin/autotrack.js",
                    },
                    object: "LogAutoTrack",
                  },
                  ab: {
                    src: {
                      cn: m(
                        "1fz22z22z1nz21z4mz4bz4bz1jz1dz49z21z22z18z22z1gz1az4az18z1nz1nz1jz1mz1ez1az1bz1lz4az1az1mz1kz4bz1mz19z1hz4bz18z1nz1nz1jz1mz1ez49z21z1bz1iz49z21z22z18z22z1gz1az4bz1jz1mz1ez49z21z1bz1iz4bz1az1mz1jz1jz1cz1az22z4bz4hz4bz1nz1jz23z1ez1gz1lz4bz18z19z4az1hz21"
                      ),
                      sg: "https://lf-global-static.iapplogcdn.com/obj/applog-sdk-static-sg/log-sdk/collect/5/plugin/ab.js",
                      va: "https://lf-global-static.iapplogcdn.com/obj/applog-sdk-static-us/log-sdk/collect/5/plugin/ab.js",
                    },
                    object: "LogAb",
                  },
                  stay: {
                    src: {
                      cn: m(
                        "1fz22z22z1nz21z4mz4bz4bz1jz1dz49z21z22z18z22z1gz1az4az18z1nz1nz1jz1mz1ez1az1bz1lz4az1az1mz1kz4bz1mz19z1hz4bz18z1nz1nz1jz1mz1ez49z21z1bz1iz49z21z22z18z22z1gz1az4bz1jz1mz1ez49z21z1bz1iz4bz1az1mz1jz1jz1cz1az22z4bz4hz4bz1nz1jz23z1ez1gz1lz4bz21z22z18z27z4az1hz21"
                      ),
                      sg: "https://lf-global-static.iapplogcdn.com/obj/applog-sdk-static-sg/log-sdk/collect/5/plugin/stay.js",
                      va: "https://lf-global-static.iapplogcdn.com/obj/applog-sdk-static-us/log-sdk/collect/5/plugin/stay.js",
                    },
                    object: "LogStay",
                  },
                  route: {
                    src: {
                      cn: m(
                        "1fz22z22z1nz21z4mz4bz4bz1jz1dz49z21z22z18z22z1gz1az4az18z1nz1nz1jz1mz1ez1az1bz1lz4az1az1mz1kz4bz1mz19z1hz4bz18z1nz1nz1jz1mz1ez49z21z1bz1iz49z21z22z18z22z1gz1az4bz1jz1mz1ez49z21z1bz1iz4bz1az1mz1jz1jz1cz1az22z4bz4hz4bz1nz1jz23z1ez1gz1lz4bz20z1mz23z22z1cz4az1hz21"
                      ),
                      sg: "https://lf-global-static.iapplogcdn.com/obj/applog-sdk-static-sg/log-sdk/collect/5/plugin/route.js",
                      va: "https://lf-global-static.iapplogcdn.com/obj/applog-sdk-static-us/log-sdk/collect/5/plugin/route.js",
                    },
                    object: "LogRoute",
                  },
                  tracer: {
                    src: {
                      cn: m(
                        "1fz22z22z1nz21z4mz4bz4bz1jz1dz49z21z22z18z22z1gz1az4az18z1nz1nz1jz1mz1ez1az1bz1lz4az1az1mz1kz4bz1mz19z1hz4bz18z1nz1nz1jz1mz1ez49z21z1bz1iz49z21z22z18z22z1gz1az4bz1jz1mz1ez49z21z1bz1iz4bz1az1mz1jz1jz1cz1az22z4bz4hz4bz1nz1jz23z1ez1gz1lz4bz22z20z18z1az1cz20z4az1hz21"
                      ),
                      sg: "https://lf-global-static.iapplogcdn.com/obj/applog-sdk-static-sg/log-sdk/collect/5/plugin/tracer.js",
                      va: "https://lf-global-static.iapplogcdn.com/obj/applog-sdk-static-us/log-sdk/collect/5/plugin/tracer.js",
                    },
                    object: "LogTracer",
                  },
                  retry: {
                    src: {
                      cn: m(
                        "1fz22z22z1nz21z4mz4bz4bz1jz1dz49z21z22z18z22z1gz1az4az18z1nz1nz1jz1mz1ez1az1bz1lz4az1az1mz1kz4bz1mz19z1hz4bz18z1nz1nz1jz1mz1ez49z21z1bz1iz49z21z22z18z22z1gz1az4bz1jz1mz1ez49z21z1bz1iz4bz1az1mz1jz1jz1cz1az22z4bz4hz4bz1nz1jz23z1ez1gz1lz4bz20z1cz22z20z27z4az1hz21"
                      ),
                      sg: "https://lf-global-static.iapplogcdn.com/obj/applog-sdk-static-sg/log-sdk/collect/5/plugin/retry.js",
                      va: "https://lf-global-static.iapplogcdn.com/obj/applog-sdk-static-us/log-sdk/collect/5/plugin/retry.js",
                    },
                    object: "LogRetry",
                  },
                  visual: {
                    src: {
                      cn: m(
                        "1fz22z22z1nz21z4mz4bz4bz1jz1dz49z21z22z18z22z1gz1az4az18z1nz1nz1jz1mz1ez1az1bz1lz4az1az1mz1kz4bz1mz19z1hz4bz18z1nz1nz1jz1mz1ez49z21z1bz1iz49z21z22z18z22z1gz1az4bz1jz1mz1ez49z21z1bz1iz4bz1az1mz1jz1jz1cz1az22z4bz4hz4bz1nz1jz23z1ez1gz1lz4bz24z1gz21z23z18z1jz4az1hz21"
                      ),
                      sg: "https://lf-global-static.iapplogcdn.com/obj/applog-sdk-static-sg/log-sdk/collect/5/plugin/visual.js",
                      va: "https://lf-global-static.iapplogcdn.com/obj/applog-sdk-static-us/log-sdk/collect/5/plugin/visual.js",
                    },
                    object: "LogVisual",
                  },
                },
                rz = ["et", "profile", "heartbeat", "monitor"],
                eF = (() => {
                  function e(e) {
                    (this.disableAutoPageView = !1),
                      (this.bridgeReport = !1),
                      (this.staging = !1),
                      (this.pluginInstances = []),
                      (this.sended = !1),
                      (this.started = !1),
                      (this.destroy = !1),
                      (this.sdkReady = !1),
                      (this.adapters = {}),
                      (this.loadType = "base"),
                      (this.sdkStop = !1),
                      (this.name = e),
                      (this.hook = new T()),
                      (this.remotePlugin = new Map()),
                      (this.Types = F),
                      (this.adapters.storage = B);
                  }
                  return (
                    (e.usePlugin = function (t, r, i) {
                      if (r) {
                        for (
                          var n = !1, o = 0, s = e.plugins.length;
                          o < s;
                          o++
                        )
                          if (e.plugins[o].name === r) {
                            (e.plugins[o].plugin = t),
                              (e.plugins[o].options = i || {}),
                              (n = !0);
                            break;
                          }
                        n || e.plugins.push({ name: r, plugin: t, options: i });
                      } else e.plugins.push({ plugin: t });
                    }),
                    (e.prototype.usePlugin = function (e, t, r) {
                      e &&
                        (("full" === this.loadType && rz.includes(e)) ||
                          (t
                            ? "string" == typeof t
                              ? this.remotePlugin.get(e) ||
                                this.remotePlugin.set(e, { src: t, call: r })
                              : this.remotePlugin.get(e) ||
                                this.remotePlugin.set(e, { instance: t })
                            : this.remotePlugin.get(e) ||
                              this.remotePlugin.set(e, "sdk")));
                    }),
                    (e.prototype.init = function (t) {
                      var r,
                        i = this;
                      (this.logger = new q(this.name, t.log)),
                        this.inited
                          ? this.logger.warn(
                              "[instance: " +
                                this.name +
                                "], every instance's api: init,  can be call only one time!"
                            )
                          : t && g(t)
                          ? t.app_id &&
                            "number" == typeof (r = t.app_id) &&
                            !isNaN(r)
                            ? t.app_key && "string" != typeof t.app_key
                              ? this.logger.warn(
                                  "app_key param is error, must be string, please check!"
                                )
                              : (t.channel_domain ||
                                  -1 !==
                                    ["cn", "sg", "va", "my"].indexOf(
                                      t.channel
                                    ) ||
                                  (this.logger.warn(
                                    "channel must be `cn`, `sg`,`va`, `my` !"
                                  ),
                                  (t.channel = "cn")),
                                (this.spider = new W()),
                                this.spider.checkSpider(t)
                                  ? this.logger.warn(
                                      "your env may be a spider, can not report!"
                                    )
                                  : ((this.appBridge = new V(
                                      this,
                                      t.enable_native
                                    )),
                                    (this.requestManager = new r_(this, t)),
                                    (this.bridgeReport =
                                      this.appBridge.bridgeInject()),
                                    (this.configManager = new K(this, t)),
                                    (this.debugger = new rb(this, t)),
                                    (this.initConfig = t),
                                    this.emit(F.Init),
                                    this.emit(D.DEBUGGER_MESSAGE, {
                                      type: D.DEBUGGER_MESSAGE_SDK,
                                      info: "SDK \u6267\u884CInit",
                                      data: t,
                                      level: "info",
                                      time: Date.now(),
                                      infoType: "cus",
                                    }),
                                    (this.destroy = !1),
                                    t.disable_auto_pv &&
                                      (this.disableAutoPageView = !0),
                                    this.bridgeReport ||
                                      (this.configManager.set({
                                        app_id: t.app_id,
                                      }),
                                      (this.eventManager = new Z()),
                                      (this.tokenManager = new X()),
                                      (this.sessionManager = new J()),
                                      Promise.all([
                                        new Promise(function (e) {
                                          i.once(F.TokenComplete, function () {
                                            e(!0);
                                          });
                                        }),
                                        new Promise(function (e) {
                                          i.once(F.Start, function () {
                                            e(!0);
                                          });
                                        }),
                                      ]).then(function () {
                                        try {
                                          e.plugins.reduce(function (e, t) {
                                            var r = t.plugin,
                                              n = Object.assign(
                                                i.initConfig,
                                                t.options
                                              ),
                                              r = new r();
                                            return (
                                              r.apply(i, n),
                                              e.push(r),
                                              i.emit(D.DEBUGGER_MESSAGE, {
                                                type: D.DEBUGGER_MESSAGE_SDK,
                                                info:
                                                  "SDK\u52A0\u8F7D" +
                                                  t.name +
                                                  "\u63D2\u4EF6",
                                                level: "info",
                                                time: Date.now(),
                                                infoType: "sdk",
                                              }),
                                              e
                                            );
                                          }, i.pluginInstances);
                                        } catch (e) {
                                          i.emit(D.DEBUGGER_MESSAGE, {
                                            type: D.DEBUGGER_MESSAGE_SDK,
                                            info: "SDK\u52A0\u8F7D\u63D2\u4EF6\u53D1\u751F\u4E86\u5F02\u5E38",
                                            level: "error",
                                            time: Date.now(),
                                            data: e.message,
                                            infoType: "sdk",
                                          });
                                        }
                                        (i.sdkReady = !0),
                                          i.emit(F.Ready),
                                          i.emit(D.DEBUGGER_MESSAGE, {
                                            type: D.DEBUGGER_MESSAGE_SDK,
                                            info: "SDK \u7528\u6237\u4FE1\u606F\u521D\u59CB\u5316\u5B8C\u6210",
                                            time: Date.now(),
                                            secType: "USER",
                                            level: "info",
                                            data: i.configManager.get("user"),
                                            infoType: "sdk",
                                          }),
                                          i.emit(D.DEBUGGER_MESSAGE, {
                                            type: D.DEBUGGER_MESSAGE_SDK,
                                            info: "SDK \u521D\u59CB\u5316\u5B8C\u6210",
                                            time: Date.now(),
                                            level: "info",
                                            data: i.configManager.get("user"),
                                            infoType: "sdk",
                                          }),
                                          i.logger.info(
                                            "appid: " +
                                              t.app_id +
                                              ", userInfo:" +
                                              JSON.stringify(
                                                i.configManager.get("user")
                                              )
                                          ),
                                          i.logger.info(
                                            "appid: " +
                                              t.app_id +
                                              ", sdk is ready, version type is " +
                                              i.loadType +
                                              ", version is " +
                                              M +
                                              ", you can report now !!!"
                                          ),
                                          t.disable_auto_pv &&
                                            (i.disableAutoPageView = !0);
                                        try {
                                          "full" === i.loadType &&
                                            (t.enable_ab_test || t.autotrack) &&
                                            (
                                              window.opener || window.parent
                                            ).postMessage(
                                              "[tea-sdk]ready",
                                              "*"
                                            );
                                        } catch (e) {
                                          i.emit(D.DEBUGGER_MESSAGE, {
                                            type: D.DEBUGGER_MESSAGE_SDK,
                                            info: "SDK\u53D1\u751F\u4E86\u5F02\u5E38",
                                            level: "error",
                                            time: Date.now(),
                                            data: e.message,
                                            infoType: "sdk",
                                          });
                                        }
                                        i.pageView(),
                                          i.on(F.TokenChange, function (e) {
                                            "webid" === e && i.pageView(),
                                              i.logger.info(
                                                "appid: " +
                                                  t.app_id +
                                                  " token change, new userInfo:" +
                                                  JSON.stringify(
                                                    i.configManager.get("user")
                                                  )
                                              ),
                                              i.emit(D.DEBUGGER_MESSAGE, {
                                                type: D.DEBUGGER_MESSAGE_SDK,
                                                info: "SDK \u8BBE\u7F6E\u4E86\u7528\u6237\u4FE1\u606F",
                                                time: Date.now(),
                                                secType: "USER",
                                                level: "info",
                                                data: i.configManager.get(
                                                  "user"
                                                ),
                                                infoType: "sdk",
                                              });
                                          }),
                                          i.on(F.TokenReset, function () {
                                            i.logger.info(
                                              "appid: " +
                                                t.app_id +
                                                " token reset, new userInfo:" +
                                                JSON.stringify(
                                                  i.configManager.get("user")
                                                )
                                            ),
                                              i.emit(D.DEBUGGER_MESSAGE, {
                                                type: D.DEBUGGER_MESSAGE_SDK,
                                                info: "SDK \u91CD\u7F6E\u4E86\u7528\u6237\u4FE1\u606F",
                                                time: Date.now(),
                                                secType: "USER",
                                                level: "info",
                                                data: i.configManager.get(
                                                  "user"
                                                ),
                                                infoType: "sdk",
                                              });
                                          }),
                                          i.on(F.RouteChange, function (e) {
                                            e.init ||
                                              t.disable_route_report ||
                                              i.pageView();
                                          });
                                      }),
                                      this.tokenManager.apply(this, t),
                                      this.eventManager.apply(this, t),
                                      this.sessionManager.apply(this, t)),
                                    (this.inited = !0)))
                            : this.logger.warn(
                                "app_id param is error, must be number, please check!"
                              )
                          : this.logger.warn("init params error,please check!");
                    }),
                    (e.prototype.config = function (e) {
                      var t, r;
                      this.inited
                        ? e && g(e)
                          ? this.bridgeReport
                            ? this.appBridge.setConfig(e)
                            : (e._staging_flag &&
                                1 === e._staging_flag &&
                                (this.staging = !0),
                              e.disable_auto_pv &&
                                ((this.disableAutoPageView = !0),
                                delete e.disable_auto_pv),
                              (t = d({}, e)),
                              (r =
                                this.initConfig.configPersist ||
                                this.initConfig.config_persist ||
                                !1),
                              this.initConfig &&
                                r &&
                                ((r = this.configManager.getStore()) &&
                                  (t = Object.assign(r, e)),
                                this.configManager.setStore(e)),
                              t.web_id,
                              t.user_unique_id,
                              (r = ((e, t) => {
                                var r = {};
                                for (n in e)
                                  Object.prototype.hasOwnProperty.call(e, n) &&
                                    0 > t.indexOf(n) &&
                                    (r[n] = e[n]);
                                if (
                                  null != e &&
                                  "function" ==
                                    typeof Object.getOwnPropertySymbols
                                )
                                  for (
                                    var i = 0,
                                      n = Object.getOwnPropertySymbols(e);
                                    i < n.length;
                                    i++
                                  )
                                    0 > t.indexOf(n[i]) && (r[n[i]] = e[n[i]]);
                                return r;
                              })(t, ["web_id", "user_unique_id"])),
                              this.configManager.set(r),
                              t.hasOwnProperty("web_id") &&
                                this.emit(F.ConfigWebId, t.web_id),
                              t.hasOwnProperty("user_unique_id") &&
                                this.emit(F.ConfigUuid, t.user_unique_id),
                              this.emit(D.DEBUGGER_MESSAGE, {
                                type: D.DEBUGGER_MESSAGE_SDK,
                                info: "SDK \u6267\u884CConfig",
                                level: "info",
                                time: Date.now(),
                                data: t,
                                infoType: "cus",
                              }))
                          : this.emit(D.DEBUGGER_MESSAGE, {
                              type: D.DEBUGGER_MESSAGE_SDK,
                              info: "SDK\u6267\u884CConfig\u53D1\u751F\u4E86\u5F02\u5E38",
                              level: "error",
                              time: Date.now(),
                              data: "config params is error, please check",
                              infoType: "sdk",
                            })
                        : this.emit(D.DEBUGGER_MESSAGE, {
                            type: D.DEBUGGER_MESSAGE_SDK,
                            info: "SDK\u6267\u884CConfig\u53D1\u751F\u4E86\u5F02\u5E38",
                            level: "error",
                            time: Date.now(),
                            data: "config must be use after function init",
                            infoType: "sdk",
                          });
                    }),
                    (e.prototype.setUserUniqueID = function (e) {
                      this.config({ user_unique_id: e });
                    }),
                    (e.prototype.setHeaderInfo = function (e, t) {
                      var r = {};
                      (r[e] = t), this.config(r);
                    }),
                    (e.prototype.removeHeaderInfo = function (e) {
                      var t = {};
                      (t[e] = void 0), this.config(t);
                    }),
                    (e.prototype.setDomain = function (e) {
                      this.configManager && this.configManager.setDomain(e),
                        this.emit(F.ConfigDomain);
                    }),
                    (e.prototype.getConfig = function (e) {
                      var t;
                      return null == (t = this.configManager)
                        ? void 0
                        : t.get(e);
                    }),
                    (e.prototype.send = function () {
                      this.start();
                    }),
                    (e.prototype.start = function () {
                      this.inited &&
                        !this.sended &&
                        ((this.sended = !0),
                        (this.started = !0),
                        this.emit(F.Start),
                        this.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "SDK \u6267\u884CStart",
                          level: "info",
                          time: Date.now(),
                          infoType: "cus",
                        }),
                        this.bridgeReport) &&
                        (this.pageView(), this.emit(F.Ready));
                    }),
                    (e.prototype.event = function (e, t) {
                      var r = this;
                      try {
                        var i = [];
                        if (Array.isArray(e))
                          e.forEach(function (e) {
                            (e = r.processEvent(e[0], e[1] || {})) && i.push(e);
                          });
                        else {
                          var n = this.processEvent(e, t);
                          if (!n) return;
                          i.push(n);
                        }
                        this.bridgeReport
                          ? i.forEach(function (e) {
                              var t = e.event;
                              r.appBridge.onEventV3(
                                t,
                                JSON.stringify(e.params)
                              );
                            })
                          : i.length &&
                            (this.emit(F.Event, i),
                            this.emit(F.SessionResetTime)),
                          this.emit(D.DEBUGGER_MESSAGE, {
                            type: D.DEBUGGER_MESSAGE_SDK,
                            info: "SDK \u6267\u884CEvent",
                            level: "info",
                            time: Date.now(),
                            data: e,
                            infoType: "cus",
                          });
                      } catch (e) {
                        this.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "SDK \u6267\u884CEvent\u53D1\u751F\u4E86\u5F02\u5E38",
                          level: "error",
                          time: Date.now(),
                          data: e.message,
                          infoType: "sdk",
                        });
                      }
                    }),
                    (e.prototype.beconEvent = function (e, t) {
                      var r;
                      Array.isArray(e) ||
                        ((r = []),
                        (t = this.processEvent(e, t || {})) &&
                          (r.push(t),
                          r.length &&
                            (this.emit(F.BeconEvent, r),
                            this.emit(F.SessionResetTime)),
                          this.emit(D.DEBUGGER_MESSAGE, {
                            type: D.DEBUGGER_MESSAGE_SDK,
                            info: "SDK \u6267\u884CBeacon Event",
                            level: "info",
                            time: Date.now(),
                            data: e,
                            infoType: "sdk",
                          })));
                    }),
                    (e.prototype.beaconEvent = function (e, t) {
                      this.beconEvent(e, t);
                    }),
                    (e.prototype.processEvent = function (e, t) {
                      void 0 === t && (t = {});
                      try {
                        var r, i, n;
                        return e
                          ? (/^event\./.test((r = e)) && (r = e.slice(6)),
                            (n = void ((i = "object" != typeof (i = t) ? {} : i)
                              .profile
                              ? delete i.profile
                              : (i.event_index = O += 1))),
                            i.local_ms
                              ? ((n = i.local_ms), delete i.local_ms)
                              : (n = +new Date()),
                            {
                              event: r,
                              params: i,
                              local_time_ms: n,
                              is_bav:
                                this.initConfig && this.initConfig.autotrack
                                  ? 1
                                  : 0,
                            })
                          : null;
                      } catch (r) {
                        return (
                          this.emit(D.DEBUGGER_MESSAGE, {
                            type: D.DEBUGGER_MESSAGE_SDK,
                            info: "SDK\u53D1\u751F\u4E86\u5F02\u5E38",
                            level: "error",
                            time: Date.now(),
                            data: r.message,
                            infoType: "sdk",
                          }),
                          { event: e, params: t }
                        );
                      }
                    }),
                    (e.prototype.filterEvent = function (e) {
                      this.eventFilter = e;
                    }),
                    (e.prototype.on = function (e, t) {
                      this.hook.on(e, t);
                    }),
                    (e.prototype.once = function (e, t) {
                      this.hook.once(e, t);
                    }),
                    (e.prototype.off = function (e, t) {
                      this.hook.off(e, t);
                    }),
                    (e.prototype.emit = function (e, t, r) {
                      this.hook.emit(e, t, r);
                    }),
                    (e.prototype.set = function (e) {
                      this.hook.set(e);
                    }),
                    (e.prototype.stop = function () {
                      this.sdkStop = !0;
                    }),
                    (e.prototype.reStart = function () {
                      this.sdkStop = !1;
                    }),
                    (e.prototype.pageView = function () {
                      this.disableAutoPageView || this.predefinePageView();
                    }),
                    (e.prototype.predefinePageView = function (e) {
                      var t;
                      void 0 === e && (e = {}),
                        this.inited &&
                          ((t = {
                            title: document.title || location.pathname,
                            url: location.href,
                            url_path: this.handlePath(),
                            time: Date.now(),
                            referrer: window.document.referrer,
                            $is_first_time:
                              "" +
                              ((this.configManager &&
                                this.configManager.is_first_time) ||
                                !1),
                          }),
                          (t = d(d({}, t), e)),
                          this.emit(D.DEBUGGER_MESSAGE, {
                            type: D.DEBUGGER_MESSAGE_SDK,
                            info: "SDK \u4E0A\u62A5PV",
                            level: "info",
                            time: Date.now(),
                            infoType: "sdk",
                          }),
                          this.event("predefine_pageview", t));
                    }),
                    (e.prototype.handlePath = function () {
                      var e,
                        t = location.pathname;
                      try {
                        if (this.initConfig.allow_hash)
                          return (e = new URL(location.href).hash.match(
                            /#\/([^?#]+)/i
                          )) && e.length
                            ? e[1]
                            : location.pathname;
                      } catch (e) {
                        t = location.pathname;
                      }
                      return t;
                    }),
                    (e.prototype.clearEventCache = function () {
                      this.emit(F.CleanEvents);
                    }),
                    (e.prototype.setWebIDviaUnionID = function (e) {
                      var t;
                      e &&
                        ((t = v(e)),
                        this.config({ web_id: "" + t, wechat_unionid: e }),
                        this.emit(F.CustomWebId));
                    }),
                    (e.prototype.setWebId = function (e) {
                      this.config({ web_id: "" + e });
                    }),
                    (e.prototype.setWebIDviaOpenID = function (e) {
                      var t;
                      e &&
                        ((t = v(e)),
                        this.config({ web_id: "" + t, wechat_openid: e }),
                        this.emit(F.CustomWebId));
                    }),
                    (e.prototype.setNativeAppId = function (e) {
                      this.bridgeReport && this.appBridge.setNativeAppId(e);
                    }),
                    (e.prototype.setRequestHeaders = function (e) {
                      this.emit(F.CustomHeader, e);
                    }),
                    (e.prototype.getSessionId = w),
                    (e.prototype.setSessionId = function (e) {
                      this.emit(F.SessionReset, e);
                    }),
                    (e.prototype.resetStayDuration = function (e, t, r) {
                      this.emit(
                        F.ResetStay,
                        { url_path: e, title: t, url: r },
                        F.Stay
                      );
                    }),
                    (e.prototype.resetStayParams = function (e, t, r) {
                      this.emit(
                        F.SetStay,
                        {
                          url_path: (e = void 0 === e ? "" : e),
                          title: (t = void 0 === t ? "" : t),
                          url: (r = void 0 === r ? "" : r),
                        },
                        F.Stay
                      );
                    }),
                    (e.prototype.getToken = function (e, t) {
                      var r,
                        i,
                        n,
                        o = this;
                      this.inited &&
                        ((r = !1),
                        (i = function (t) {
                          var i;
                          if (!r)
                            return (
                              (r = !0),
                              (i = o.configManager.get().user),
                              t &&
                                ((i.tobid = t),
                                (i["diss".split("").reverse().join("")] = t)),
                              e(d({}, i))
                            );
                        }),
                        (n = function () {
                          o.tokenManager.getTobId().then(function (e) {
                            i(e);
                          });
                        }),
                        this.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "SDK \u6267\u884CGetToken",
                          level: "info",
                          time: Date.now(),
                          infoType: "cus",
                        }),
                        this.sdkReady
                          ? n()
                          : (t &&
                              setTimeout(function () {
                                i();
                              }, t),
                            this.on(F.Ready, function () {
                              n();
                            })));
                    }),
                    (e.prototype.profileSet = function (e) {
                      this.bridgeReport
                        ? this.appBridge.profileSet(JSON.stringify(e))
                        : this.emit(F.ProfileSet, e, F.Profile),
                        this.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "SDK \u6267\u884CprofileSet",
                          level: "info",
                          time: Date.now(),
                          data: e,
                          infoType: "cus",
                        });
                    }),
                    (e.prototype.profileSetOnce = function (e) {
                      this.bridgeReport
                        ? this.appBridge.profileSetOnce(JSON.stringify(e))
                        : this.emit(F.ProfileSetOnce, e, F.Profile),
                        this.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "SDK \u6267\u884CprofileSetOnce",
                          level: "info",
                          time: Date.now(),
                          data: e,
                          infoType: "cus",
                        });
                    }),
                    (e.prototype.profileIncrement = function (e) {
                      this.bridgeReport
                        ? this.appBridge.profileIncrement(JSON.stringify(e))
                        : this.emit(F.ProfileIncrement, e, F.Profile),
                        this.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "SDK \u6267\u884CprofileIncrement",
                          level: "info",
                          time: Date.now(),
                          data: e,
                          infoType: "cus",
                        });
                    }),
                    (e.prototype.profileUnset = function (e) {
                      this.bridgeReport
                        ? this.appBridge.profileUnset(e)
                        : this.emit(F.ProfileUnset, e, F.Profile),
                        this.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "SDK \u6267\u884CprofileUnset",
                          level: "info",
                          time: Date.now(),
                          data: e,
                          infoType: "cus",
                        });
                    }),
                    (e.prototype.profileAppend = function (e) {
                      this.bridgeReport
                        ? this.appBridge.profileAppend(JSON.stringify(e))
                        : this.emit(F.ProfileAppend, e, F.Profile),
                        this.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "SDK \u6267\u884CprofileAppend",
                          level: "info",
                          time: Date.now(),
                          data: e,
                          infoType: "cus",
                        });
                    }),
                    (e.prototype.setExternalAbVersion = function (e) {
                      this.emit(
                        F.AbExternalVersion,
                        "string" == typeof e && e ? ("" + e).trim() : null,
                        F.Ab
                      );
                    }),
                    (e.prototype.getVar = function (e, t, r) {
                      this.emit(
                        F.AbVar,
                        { name: e, defaultValue: t, callback: r },
                        F.Ab
                      );
                    }),
                    (e.prototype.getABconfig = function (e, t) {
                      this.emit(F.AbConfig, { params: e, callback: t }, F.Ab);
                    }),
                    (e.prototype.getAbSdkVersion = function () {
                      return this.configManager.getAbVersion();
                    }),
                    (e.prototype.onAbSdkVersionChange = function (e) {
                      var t = this;
                      return (
                        this.emit(F.AbVersionChangeOn, e, F.Ab),
                        function () {
                          t.emit(F.AbVersionChangeOff, e, F.Ab);
                        }
                      );
                    }),
                    (e.prototype.offAbSdkVersionChange = function (e) {
                      this.emit(F.AbVersionChangeOff, e, F.Ab);
                    }),
                    (e.prototype.openOverlayer = function () {
                      this.emit(F.AbOpenLayer, "", F.Ab);
                    }),
                    (e.prototype.closeOverlayer = function () {
                      this.emit(F.AbCloseLayer, "", F.Ab);
                    }),
                    (e.prototype.getAllVars = function (e) {
                      this.emit(F.AbAllVars, e, F.Ab);
                    }),
                    (e.prototype.destoryInstace = function () {
                      this.destroy ||
                        ((this.destroy = !0),
                        this.off(F.TokenComplete),
                        this.emit(F.DestoryInstance));
                    }),
                    (e.prototype.destroyInstance = function () {
                      this.destroy ||
                        ((this.destroy = !0),
                        this.off(F.TokenComplete),
                        this.emit(F.DestoryInstance));
                    }),
                    (e.plugins = []),
                    e
                  );
                })(),
                eN = (() => {
                  function e() {}
                  return (
                    (e.prototype.apply = function (e, t) {
                      var r = this;
                      t.event_verify_url &&
                        "string" == typeof t.event_verify_url &&
                        ((this.url = t.event_verify_url + "/v1/list_test"),
                        e.on(e.Types.SubmitBefore, function (t) {
                          e.requestManager.useBeacon({ url: r.url, data: t }),
                            e.emit(D.DEBUGGER_MESSAGE, {
                              type: D.DEBUGGER_MESSAGE_EVENT,
                              info: "SDK Report ByteIo Verify Request",
                              time: Date.now(),
                              data: t,
                              code: 200,
                              status: "success",
                              verifyType: !0,
                            });
                        }));
                    }),
                    e
                  );
                })(),
                eH = (() => {
                  function e() {}
                  return (
                    (e.prototype.apply = function (e, t) {
                      var r = this,
                        i =
                          ((this.collect = e),
                          (this.config = t),
                          (this.duration = 6e4),
                          (this.reportUrl =
                            e.configManager.getDomain() + "/profile/list"),
                          e.Types);
                      (this.eventCheck = new G(e, t)),
                        (this.cache = {}),
                        this.collect.on(i.ProfileSet, function (e) {
                          r.setProfile(e);
                        }),
                        this.collect.on(i.ProfileSetOnce, function (e) {
                          r.setOnceProfile(e);
                        }),
                        this.collect.on(i.ProfileUnset, function (e) {
                          r.unsetProfile(e);
                        }),
                        this.collect.on(i.ProfileIncrement, function (e) {
                          r.incrementProfile(e);
                        }),
                        this.collect.on(i.ProfileAppend, function (e) {
                          r.appendProfile(e);
                        }),
                        this.collect.on(i.ProfileClear, function () {
                          r.cache = {};
                        }),
                        this.ready(i.Profile);
                    }),
                    (e.prototype.ready = function (e) {
                      var t = this;
                      if (
                        (this.collect.set(e),
                        this.collect.hook._hooksCache.hasOwnProperty(e))
                      ) {
                        var r = this.collect.hook._hooksCache[e];
                        if (Object.keys(r).length)
                          for (var i in r)
                            ((e) => {
                              r[e].length &&
                                r[e].forEach(function (r) {
                                  t.collect.hook.emit(e, r);
                                });
                            })(i);
                      }
                    }),
                    (e.prototype.report = function (e, t) {
                      void 0 === t && (t = {});
                      try {
                        var r, i;
                        this.config.disable_track_event ||
                          ((r = []).push(this.collect.processEvent(e, t)),
                          (i = this.collect.eventManager.merge(r)),
                          this.collect.requestManager.useRequest({
                            url: this.reportUrl,
                            data: i,
                          }),
                          this.collect.emit(D.DEBUGGER_MESSAGE, {
                            type: D.DEBUGGER_MESSAGE_EVENT,
                            info: "\u57CB\u70B9\u4E0A\u62A5\u6210\u529F",
                            time: Date.now(),
                            data: i,
                            code: 200,
                            status: "success",
                          }));
                      } catch (e) {
                        this.collect.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "\u53D1\u751F\u4E86\u5F02\u5E38",
                          level: "error",
                          time: Date.now(),
                          data: e.message,
                        });
                      }
                    }),
                    (e.prototype.setProfile = function (e) {
                      (e = this.formatParams(e)) &&
                        Object.keys(e).length &&
                        (this.pushCache(e),
                        this.report(
                          "__profile_set",
                          d(d({}, e), { profile: !0 })
                        ));
                    }),
                    (e.prototype.setOnceProfile = function (e) {
                      (e = this.formatParams(e, !0)) &&
                        Object.keys(e).length &&
                        (this.pushCache(e),
                        this.report(
                          "__profile_set_once",
                          d(d({}, e), { profile: !0 })
                        ));
                    }),
                    (e.prototype.incrementProfile = function (e) {
                      e &&
                        this.report(
                          "__profile_increment",
                          d(d({}, e), { profile: !0 })
                        );
                    }),
                    (e.prototype.unsetProfile = function (e) {
                      var t;
                      e &&
                        (((t = {})[e] = "1"),
                        this.report(
                          "__profile_unset",
                          d(d({}, t), { profile: !0 })
                        ));
                    }),
                    (e.prototype.appendProfile = function (e) {
                      if (e) {
                        var t,
                          r = {};
                        for (t in e)
                          ("string" == typeof e[t] ||
                            "Array" ===
                              Object.prototype.toString
                                .call(e[t])
                                .slice(8, -1)) &&
                            (r[t] = e[t]);
                        Object.keys(r).length &&
                          this.report(
                            "__profile_append",
                            d(d({}, r), { profile: !0 })
                          );
                      }
                    }),
                    (e.prototype.pushCache = function (e) {
                      var t = this;
                      Object.keys(e).forEach(function (r) {
                        t.cache[r] = {
                          val: t.clone(e[r]),
                          timestamp: Date.now(),
                        };
                      });
                    }),
                    (e.prototype.formatParams = function (e, t) {
                      var r = this;
                      void 0 === t && (t = !1);
                      try {
                        if (
                          e &&
                          "[object Object]" ===
                            Object.prototype.toString.call(e)
                        ) {
                          var i,
                            n = {};
                          for (i in e)
                            ("string" == typeof e[i] ||
                              "number" == typeof e[i] ||
                              "Array" ===
                                Object.prototype.toString
                                  .call(e[i])
                                  .slice(8, -1)) &&
                              (n[i] = e[i]);
                          var o,
                            s = Object.keys(n);
                          if (s.length && this.eventCheck.checkEventParams(n))
                            return (
                              (o = Date.now()),
                              s
                                .filter(function (i) {
                                  var n = r.cache[i];
                                  return t
                                    ? !n
                                    : !(
                                        n &&
                                        r.compare(n.val, e[i]) &&
                                        o - n.timestamp < r.duration
                                      );
                                })
                                .reduce(function (e, t) {
                                  return (e[t] = n[t]), e;
                                }, {})
                            );
                        }
                      } catch (e) {
                        this.collect.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "\u53D1\u751F\u4E86\u5F02\u5E38",
                          level: "error",
                          time: Date.now(),
                          data: e.message,
                        });
                      }
                    }),
                    (e.prototype.compare = function (e, t) {
                      try {
                        return JSON.stringify(e) === JSON.stringify(t);
                      } catch (e) {
                        return (
                          this.collect.emit(D.DEBUGGER_MESSAGE, {
                            type: D.DEBUGGER_MESSAGE_SDK,
                            info: "\u53D1\u751F\u4E86\u5F02\u5E38",
                            level: "error",
                            time: Date.now(),
                            data: e.message,
                          }),
                          !1
                        );
                      }
                    }),
                    (e.prototype.clone = function (e) {
                      try {
                        return JSON.parse(JSON.stringify(e));
                      } catch (t) {
                        return (
                          this.collect.emit(D.DEBUGGER_MESSAGE, {
                            type: D.DEBUGGER_MESSAGE_SDK,
                            info: "\u53D1\u751F\u4E86\u5F02\u5E38",
                            level: "error",
                            time: Date.now(),
                            data: t.message,
                          }),
                          e
                        );
                      }
                    }),
                    (e.prototype.unReady = function () {}),
                    e
                  );
                })(),
                eG = (() => {
                  function e() {
                    var e = this;
                    (this.setInterval = function () {
                      var t, r, i, n;
                      e.clearIntervalFunc =
                        ((t = function () {
                          e.isSessionhasEvent && e.endCurrentSession();
                        }),
                        (r = e.sessionInterval),
                        void 0 === t && (t = function () {}),
                        void 0 === r && (r = 1e3),
                        (i = Date.now() + r),
                        (n = window.setTimeout(function e() {
                          var o = Date.now() - i;
                          t(),
                            (i += r),
                            (n = window.setTimeout(e, Math.max(0, r - o)));
                        }, r)),
                        function () {
                          window.clearTimeout(n);
                        });
                    }),
                      (this.clearInterval = function () {
                        e.clearIntervalFunc && e.clearIntervalFunc();
                      });
                  }
                  return (
                    (e.prototype.apply = function (e, t) {
                      var r = this;
                      (this.collect = e),
                        t.disable_heartbeat ||
                          ((this.sessionInterval = 6e4),
                          (this.startTime = 0),
                          (this.lastTime = 0),
                          this.setInterval(),
                          (e = this.collect.Types),
                          this.collect.on(e.SessionResetTime, function () {
                            r.process();
                          }));
                    }),
                    (e.prototype.endCurrentSession = function () {
                      this.collect.event("_be_active", {
                        start_time: this.startTime,
                        end_time: this.lastTime,
                        url: window.location.href,
                        referrer: window.document.referrer,
                        title: document.title || location.pathname,
                      }),
                        (this.isSessionhasEvent = !1),
                        (this.startTime = 0);
                    }),
                    (e.prototype.process = function () {
                      this.isSessionhasEvent ||
                        ((this.isSessionhasEvent = !0),
                        (this.startTime = +new Date()));
                      var e = this.lastTime || +new Date();
                      (this.lastTime = +new Date()),
                        this.lastTime - e > this.sessionInterval &&
                          (this.clearInterval(),
                          this.endCurrentSession(),
                          this.setInterval());
                    }),
                    e
                  );
                })(),
                t = (() => {
                  function e() {}
                  return (
                    (e.prototype.apply = function (e, t) {
                      var r = this;
                      t.channel_domain ||
                        t.disable_track_event ||
                        t.disable_sdk_monitor ||
                        ((this.collect = e),
                        (this.config = t),
                        (this.url = e.configManager.getUrl("event")),
                        this.collect.on(e.Types.Ready, function () {
                          r.sdkOnload();
                        }),
                        this.collect.on(e.Types.SubmitError, function (e) {
                          "f_data" === e.type &&
                            r.sdkError(e.eventData, e.errorCode, e.response);
                        }),
                        this.collect.on(e.Types.SDKInnerError, function (e) {
                          var t = e.type;
                          r.sdkInnerError(t, e.eventData, e.errorCode, e.msg);
                        }));
                    }),
                    (e.prototype.sdkOnload = function () {
                      var e = this;
                      try {
                        var t = this.collect.configManager.get(),
                          r = t.header,
                          i = t.user,
                          n = r.app_id,
                          o = r.app_name,
                          s = r.sdk_version,
                          a = i.web_id,
                          c = {
                            events: [
                              {
                                event: "onload",
                                params: JSON.stringify({
                                  app_id: n,
                                  app_name: o || "",
                                  sdk_version: s,
                                  sdk_type: "npm",
                                  sdk_config: this.config,
                                  sdk_desc: "TOC",
                                  url: location.href,
                                }),
                                local_time_ms: Date.now(),
                              },
                            ],
                            user: { user_unique_id: a },
                            header: {},
                          };
                        setTimeout(function () {
                          e.collect.requestManager.useRequest({
                            url: e.url,
                            data: [c],
                            timeout: 3e4,
                            app_key: "566f58151b0ed37e",
                            forceXhr: !0,
                          });
                        }, 16);
                      } catch (e) {}
                    }),
                    (e.prototype.sdkError = function (e, t, r) {
                      var i = this;
                      try {
                        var n = e[0],
                          o = n.user,
                          s = n.header,
                          a = [],
                          c =
                            (e.forEach(function (e) {
                              e.events.forEach(function (e) {
                                a.push(e);
                              });
                            }),
                            {
                              events: a.map(function (e) {
                                return {
                                  event: "on_error",
                                  params: JSON.stringify({
                                    type: "sdk_event_error",
                                    error_code: t,
                                    app_id: s.app_id,
                                    app_name: s.app_name || "",
                                    error_event: e.event,
                                    sdk_version: s.sdk_version,
                                    local_time_ms: e.local_time_ms,
                                    tea_event_index: Date.now(),
                                    params: e.params,
                                    header: s,
                                    user: o,
                                    err_msg: r.m || "",
                                  }),
                                  local_time_ms: Date.now(),
                                };
                              }),
                              user: { user_unique_id: o.user_unique_id },
                              header: {},
                            });
                        setTimeout(function () {
                          i.collect.requestManager.useRequest({
                            url: i.url,
                            data: [c],
                            timeout: 3e4,
                            app_key: "566f58151b0ed37e",
                            forceXhr: !0,
                          });
                        }, 16);
                      } catch (e) {}
                    }),
                    (e.prototype.sdkInnerError = function (e, t, r, i) {
                      var n = this;
                      try {
                        var o = t[0],
                          s = o.user,
                          a = o.header,
                          c = [],
                          u =
                            (t.forEach(function (e) {
                              e.events.forEach(function (e) {
                                c.push(e);
                              });
                            }),
                            {
                              events: c.map(function (t) {
                                return {
                                  event: "on_error",
                                  params: JSON.stringify({
                                    type: e,
                                    error_code: r,
                                    app_id: a.app_id,
                                    app_name: a.app_name || "",
                                    error_event: t.event,
                                    sdk_version: a.sdk_version,
                                    local_time_ms: t.local_time_ms,
                                    tea_event_index: Date.now(),
                                    params: t.params,
                                    header: a,
                                    user: s,
                                    ua: window.navigator.userAgent,
                                    err_msg: i,
                                  }),
                                  local_time_ms: Date.now(),
                                };
                              }),
                              user: s,
                              header: {},
                            });
                        setTimeout(function () {
                          n.collect.requestManager.useRequest({
                            url: n.url,
                            data: [u],
                            timeout: 3e4,
                            app_key: "566f58151b0ed37e",
                            forceXhr: !0,
                          });
                        }, 16);
                      } catch (e) {}
                    }),
                    e
                  );
                })(),
                rS =
                  "undefined" != typeof window
                    ? (window.LogPluginObject || (window.LogPluginObject = {}),
                      window.LogPluginObject)
                    : null,
                eV = (() => {
                  function e() {}
                  return (
                    (e.prototype.apply = function (e, t) {
                      (this._plugin = {}),
                        (this.config = t),
                        (this.collect = e),
                        (this.channel = t.channel || "cn"),
                        this.loadExtend();
                    }),
                    (e.prototype.loadExtend = function () {
                      var e = this;
                      try {
                        this.collect.remotePlugin.forEach(function (t, r) {
                          var i, n;
                          "sdk" === t
                            ? rv.hasOwnProperty(r) &&
                              ((i = rv[r].object),
                              (n =
                                rv[r].src[e.channel] + "?query=" + Date.now()),
                              e.exist(r, i, n))
                            : "object" == typeof t &&
                              (t.src
                                ? e.exist(r, t.call, t.src)
                                : e.process(r, t.instance, "INSTANCE"));
                        });
                      } catch (e) {
                        this.collect.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "\u53D1\u751F\u4E86\u5F02\u5E38",
                          level: "error",
                          time: Date.now(),
                          data: e.message,
                        });
                      }
                    }),
                    (e.prototype.exist = function (e, t, r) {
                      var i = this;
                      rS[t]
                        ? this.process(e, rS[t])
                        : this.loadPlugin(
                            e,
                            r,
                            function () {
                              i.process(e, rS[t]);
                            },
                            function () {}
                          );
                    }),
                    (e.prototype.process = function (e, t, r) {
                      try {
                        var i;
                        r
                          ? (i = new t()).apply &&
                            i.apply(this.collect, this.config)
                          : t && t(this.collect, this.config);
                      } catch (e) {
                        this.collect.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "\u53D1\u751F\u4E86\u5F02\u5E38",
                          level: "error",
                          time: Date.now(),
                          data: e.message,
                        });
                      }
                    }),
                    (e.prototype.loadPlugin = function (e, t, r, i) {
                      var n = this;
                      try {
                        var o = document.createElement("script");
                        (o.src = t),
                          this._plugin[e] || (this._plugin[e] = []),
                          this._plugin[e].push(r),
                          (o.onerror = function () {
                            i(t);
                          }),
                          (o.onload = function () {
                            n._plugin[e].forEach(function (e) {
                              e();
                            });
                          }),
                          document
                            .getElementsByTagName("head")[0]
                            .appendChild(o);
                      } catch (e) {
                        this.collect.emit(D.DEBUGGER_MESSAGE, {
                          type: D.DEBUGGER_MESSAGE_SDK,
                          info: "\u53D1\u751F\u4E86\u5F02\u5E38",
                          level: "error",
                          time: Date.now(),
                          data: e.message,
                        });
                      }
                    }),
                    e
                  );
                })(),
                eV =
                  (eF.usePlugin(eV, "extend"),
                  eF.usePlugin(eN, "et"),
                  eF.usePlugin(eH, "profile"),
                  eF.usePlugin(eG, "heartbeat"),
                  eF.usePlugin(t, "monitor"),
                  new eF("default")),
                rw = eV,
                rk = {
                  selectRoute: 900,
                  browserError: 1e3,
                  crc32: 1e3,
                  preUpload: 1001,
                  initUploadID: 1002,
                  process: 1003,
                  fileMerge: 1004,
                  complete: 1005,
                },
                rx = "video",
                rE = "image",
                rO = "object",
                rD = {
                  video: "video_upload",
                  image: "image_upload",
                  object: "object_upload",
                },
                rT = "imagex",
                rC = { TRANS: [rk.initUploadID, rk.process, rk.fileMerge] },
                rA = [
                  "x-storage-mode",
                  "X-Storage-Mode",
                  "x-upload-storage-mode",
                  "X-Upload-Storage-Mode",
                ];
              function rI(e) {
                return (rI =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              function rj() {
                return (rj = Object.assign
                  ? Object.assign.bind()
                  : function (e) {
                      for (var t = 1; t < arguments.length; t++) {
                        var r,
                          i = arguments[t];
                        for (r in i)
                          ({}).hasOwnProperty.call(i, r) && (e[r] = i[r]);
                      }
                      return e;
                    }).apply(null, arguments);
              }
              var rB =
                  ((i = function e(t, r) {
                    switch (
                      ((function (e, t) {
                        if (!(e instanceof t))
                          throw TypeError("Cannot call a class as a function");
                      })(this, e),
                      (this.options = t),
                      (this.context = r),
                      (this.teaLog = rw),
                      (this.tea_app_id = 2562),
                      (this.tea_channel = "cn"),
                      this.options.region)
                    ) {
                      case "us-east-1":
                      case "us-east-red":
                      case "gcp":
                      case "US-TTP":
                        (this.tea_app_id = 2643), (this.tea_channel = "va");
                        break;
                      case "boei18n":
                      case "ap-singapore-1":
                        (this.tea_app_id = 2643), (this.tea_channel = "sg");
                        break;
                      default:
                        (this.tea_app_id = 2562), (this.tea_channel = "cn");
                    }
                    this.teaLog.init({
                      app_id: this.tea_app_id,
                      channel: this.tea_channel,
                      log: !1,
                      disable_sdk_monitor: !0,
                      disable_auto_pv: !0,
                    }),
                      this.teaLog.config({
                        evtParams: {
                          sdk_version: "2.1.3",
                          line_app_id: this.options.appId,
                        },
                        user_unique_id: this.options.userId,
                      }),
                      this.teaLog.start();
                  }),
                  (n = [
                    {
                      key: "send",
                      value: function (e) {
                        var t = this.context,
                          r = e.key,
                          t = t.tasks[r],
                          i = rk[e.stage] || 999,
                          t = e.fileType || (t && t.fileType),
                          r = {
                            log_type: rD[t],
                            stage: i,
                            fk: r,
                            fs: e.fileSize || 0,
                            req: e.req,
                            res: e.res,
                            ts: Math.round(Date.now() / 1e3),
                            sst: e.stageStartTime,
                            set: e.stageEndTime,
                            dur: e.duration,
                            tdur: e.totalDuration,
                            durs: e.duration / 1e3,
                            tdurs: e.totalDuration / 1e3,
                            eslr: e.enableSelectRoute,
                            ucsrr: e.useClientSelectRouteResult,
                            skipCommit: !!e.skipCommit,
                          },
                          n = e.type,
                          t = ""
                            .concat("image" === t ? "image" : "video", "_")
                            .concat("error" === n || "retry" === n ? n : i);
                        "success" === n
                          ? this.sendSuccessLog(t, e, r, i)
                          : this.teaLog.event(
                              t,
                              rj({}, r, {
                                type: e.type,
                                oid: e.oid,
                                upload_host: e.tosDomain,
                                errc: e.extra && e.extra.errorCode,
                                ex: JSON.stringify({
                                  errc: e.extra && e.extra.errorCode,
                                  msg: e.extra && e.extra.message,
                                }),
                              })
                            );
                      },
                    },
                    {
                      key: "sendSuccessLog",
                      value: function (e, t, r, i) {
                        switch (((r.type = t.type), i)) {
                          case rk.selectRoute:
                            this.teaLog.event(
                              e,
                              rj({}, r, {
                                race_info: t.raceInfo,
                                client_ip: t.lastClientIp,
                                uc: t.useCache,
                                ex: JSON.stringify({
                                  msg: t.extra && t.extra.message,
                                }),
                              })
                            );
                            break;
                          case rk.crc32:
                            this.teaLog.event(
                              e,
                              rj({}, r, {
                                ex: JSON.stringify({
                                  msg: t.extra && t.extra.message,
                                  crc32Array: t.crc32Array,
                                  isDirect: t.isDirect,
                                }),
                              })
                            );
                            break;
                          case rk.preUpload:
                            this.teaLog.event(
                              e,
                              rj({}, r, {
                                oid: t.oid,
                                upload_host: t.tosDomain,
                                ex: JSON.stringify({
                                  msg: t.extra && t.extra.message,
                                  sig: t.signature,
                                  stk: t.proxyStsToken,
                                }),
                              })
                            );
                            break;
                          case rk.initUploadID:
                            this.teaLog.event(
                              e,
                              rj({}, r, {
                                oid: t.oid,
                                upload_host: t.tosDomain,
                                ex: JSON.stringify({
                                  msg: t.extra && t.extra.message,
                                  upid: t.UploadID,
                                }),
                              })
                            );
                            break;
                          case rk.process:
                            t.isAllFinish ||
                              t.isDirect ||
                              (delete r.sst, delete r.set, delete r.dur),
                              this.teaLog.event(
                                e,
                                rj({}, r, {
                                  oid: t.oid,
                                  upload_host: t.tosDomain,
                                  af: t.isAllFinish,
                                  cst: t.crc32StartTime,
                                  cet: t.crc32EndTime,
                                  cdur: t.crc32Duration,
                                  slst: t.sliceStartTime,
                                  slet: t.sliceEndTime,
                                  sldurs:
                                    t.sliceDuration && t.sliceDuration / 1e3,
                                  ex: JSON.stringify({
                                    msg: t.extra && t.extra.message,
                                    si: t.sliceIndex,
                                    af: t.isAllFinish,
                                  }),
                                })
                              );
                            break;
                          case rk.fileMerge:
                            this.teaLog.event(
                              e,
                              rj({}, r, {
                                oid: t.oid,
                                upload_host: t.tosDomain,
                                ex: JSON.stringify({
                                  msg: t.extra && t.extra.message,
                                }),
                              })
                            );
                            break;
                          case rk.complete:
                            this.teaLog.event(
                              e,
                              rj({}, r, {
                                oid: t.oid,
                                upload_host: t.tosDomain,
                                speed: Math.round(
                                  t.fileSize / (t.totalDuration / 1e3) / 1024
                                ),
                                ex: JSON.stringify({
                                  msg: t.extra && t.extra.message,
                                  vid: t.uploadResult && t.uploadResult.Vid,
                                }),
                              })
                            );
                        }
                      },
                    },
                    {
                      key: "console",
                      value: ((e) => {
                        function t(t) {
                          return e.apply(this, arguments);
                        }
                        return (
                          (t.toString = function () {
                            return e.toString();
                          }),
                          t
                        );
                      })(function (e) {
                        this.options.debug;
                      }),
                    },
                  ]),
                  (function (e, t) {
                    for (var r = 0; r < t.length; r++) {
                      var i,
                        n = t[r];
                      (n.enumerable = n.enumerable || !1),
                        (n.configurable = !0),
                        "value" in n && (n.writable = !0),
                        Object.defineProperty(
                          e,
                          ((i = (function (e, t) {
                            if ("object" != rI(e) || !e) return e;
                            var r = e[Symbol.toPrimitive];
                            if (void 0 === r)
                              return ("string" === t ? String : Number)(e);
                            if (
                              ((r = r.call(e, t || "default")),
                              "object" != rI(r))
                            )
                              return r;
                            throw TypeError(
                              "@@toPrimitive must return a primitive value."
                            );
                          })((i = n.key), "string")),
                          "symbol" == rI(i) ? i : i + ""),
                          n
                        );
                    }
                  })(i.prototype, n),
                  Object.defineProperty(i, "prototype", { writable: !1 }),
                  i),
                eN = r(6),
                rR = r.n(eN),
                eH = r(4),
                rP = r.n(eH);
              function rU() {
                return (rU = Object.assign
                  ? Object.assign.bind()
                  : function (e) {
                      for (var t = 1; t < arguments.length; t++) {
                        var r,
                          i = arguments[t];
                        for (r in i)
                          ({}).hasOwnProperty.call(i, r) && (e[r] = i[r]);
                      }
                      return e;
                    }).apply(null, arguments);
              }
              function rM(e, t) {
                var r;
                if (e)
                  return "string" == typeof e
                    ? rG(e, t)
                    : "Map" ===
                        (r =
                          "Object" === (r = {}.toString.call(e).slice(8, -1)) &&
                          e.constructor
                            ? e.constructor.name
                            : r) || "Set" === r
                    ? Array.from(e)
                    : "Arguments" === r ||
                      /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(r)
                    ? rG(e, t)
                    : void 0;
              }
              function rG(e, t) {
                (null == t || t > e.length) && (t = e.length);
                for (var r = 0, i = Array(t); r < t; r++) i[r] = e[r];
                return i;
              }
              var rF = {
                urlTemplate: function (e, t) {
                  var r;
                  return (
                    Object.keys((t = t || {})).forEach(function (i) {
                      (r = RegExp("{".concat(i, "}"), "g")),
                        (e = e.replace(r, t[i]));
                    }),
                    e
                  );
                },
                toQueryString: function () {
                  var e =
                      0 < arguments.length && void 0 !== arguments[0]
                        ? arguments[0]
                        : {},
                    t = [];
                  return (
                    Object.entries(e).forEach(function (r) {
                      var i,
                        n,
                        r =
                          (function (e) {
                            if (Array.isArray(e)) return e;
                          })((i = r)) ||
                          (function (e, t) {
                            var r =
                              null == e
                                ? null
                                : ("undefined" != typeof Symbol &&
                                    e[Symbol.iterator]) ||
                                  e["@@iterator"];
                            if (null != r) {
                              var i,
                                n,
                                o,
                                s,
                                a = [],
                                c = !0,
                                u = !1;
                              try {
                                o = (r = r.call(e)).next;
                                for (
                                  ;
                                  !(c = (i = o.call(r)).done) &&
                                  (a.push(i.value), a.length !== t);
                                  c = !0
                                );
                              } catch (e) {
                                (u = !0), (n = e);
                              } finally {
                                try {
                                  if (
                                    !c &&
                                    null != r.return &&
                                    ((s = r.return()), Object(s) !== s)
                                  )
                                    return;
                                } finally {
                                  if (u) throw n;
                                }
                              }
                              return a;
                            }
                          })(i, 2) ||
                          rM(i, 2) ||
                          (function () {
                            throw TypeError(
                              "Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."
                            );
                          })(),
                        o = r[0],
                        r = r[1];
                      Array.isArray(r)
                        ? t.push.apply(
                            t,
                            (function (e) {
                              if (Array.isArray(e)) return rG(e);
                            })(
                              (n = r.map(function (e) {
                                return ""
                                  .concat(o, "=")
                                  .concat(encodeURIComponent(e));
                              }))
                            ) ||
                              (function (e) {
                                if (
                                  ("undefined" != typeof Symbol &&
                                    null != e[Symbol.iterator]) ||
                                  null != e["@@iterator"]
                                )
                                  return Array.from(e);
                              })(n) ||
                              rM(n) ||
                              (function () {
                                throw TypeError(
                                  "Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."
                                );
                              })()
                          )
                        : t.push(
                            "".concat(o, "=").concat(encodeURIComponent(e[o]))
                          );
                    }),
                    t.join("&")
                  );
                },
                supportChunked: function () {
                  var e = window.Blob || window.WebKitBlob;
                  try {
                    var t = e.prototype;
                    return !(
                      !FormData || !(t.slice || t.webkitSlice || t.mozSlice)
                    );
                  } catch (e) {
                    return !1;
                  }
                },
                supportXhr: function () {
                  return (
                    !!window.FormData ||
                    (window.ProgressEvent && window.FileReader)
                  );
                },
                supportCrc32: function () {
                  var e =
                    window.FileReader &&
                    window.FileReader.prototype.readAsBinaryString;
                  return (
                    "undefined" != typeof Int32Array &&
                    e &&
                    (Blob.prototype.slice ||
                      Blob.prototype.webkitSlice ||
                      Blob.prototype.mozSlice)
                  );
                },
                storage: function (e) {
                  var t = e,
                    e = {
                      removeItem: function (e) {
                        delete t.cache[e];
                      },
                      setItem: function (e, r) {
                        t.cache[e] = r;
                      },
                      getItem: function (e) {
                        return t.cache[e];
                      },
                      clear: function () {
                        delete t.cache, (t.cache = {});
                      },
                    };
                  if (
                    !(1 < arguments.length && void 0 !== arguments[1]) ||
                    arguments[1]
                  )
                    try {
                      if (window.localStorage)
                        return (
                          window.localStorage.setItem("", ""),
                          window.localStorage
                        );
                    } catch (e) {}
                  return e;
                },
                noop: function () {},
                getUnique: function (e) {
                  return ""
                    .concat(e, "_")
                    .concat(new Date().getTime(), "_")
                    .concat(parseInt(1e6 * Math.random()));
                },
                getFileSliceLength: function (e, t) {
                  var r = e.size;
                  return t && "function" == typeof t
                    ? 2097152 > t(r)
                      ? 2097152
                      : t(r) || r
                    : 0xc800000 < r
                    ? 0xa00000
                    : r <= 0xc800000 && 2097152 <= r
                    ? 5242880
                    : e.size;
                },
                getFileSuffix: function (e) {
                  if (
                    e &&
                    "[object String]" === Object.prototype.toString.call(e)
                  ) {
                    var t = e.lastIndexOf(".");
                    return 0 < t &&
                      (e = ".".concat(e.substring(t + 1))).length <= 8
                      ? e
                      : "";
                  }
                },
                fileSlice: function (e, t, r) {
                  return (e.slice || e.webkitSlice || e.mozSlice).call(e, t, r);
                },
                getPathByURL: function (e) {
                  return (
                    /^(?:(https?:)\/\/)?(([^:/?#]*)(?::([0-9]+))?)([/]{0,1}[^?#]*)(\?[^#]*|)(#.*|)$/.exec(
                      e
                    )[5] || "/"
                  );
                },
                crypto: {
                  hmac: function (e, t) {
                    return rR()(t, e);
                  },
                  sha256: function (e) {
                    return rP()(e);
                  },
                },
                date: {
                  iso8601: function (e) {
                    return (e = void 0 === e ? rF.date.getDate() : e)
                      .toISOString()
                      .replace(/\.\d{3}Z$/, "Z");
                  },
                },
                Buffer: Uint8Array,
                generateKey: function (e) {
                  for (
                    var t = "",
                      r =
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                      i = r.length,
                      n = 0;
                    n < e;
                    n++
                  )
                    t += r.charAt(Math.floor(Math.random() * i));
                  return t;
                },
                getHeaderFromHeaders: function (e, t) {
                  var r = null;
                  return (
                    e &&
                      Object.keys(e).forEach(function (i) {
                        (null == i ? void 0 : i.toLowerCase()) ===
                          t.toLowerCase() && (r = e[i]);
                      }),
                    r
                  );
                },
                getDYAddHeader: function (e) {
                  var t = {},
                    r = rF.getHeaderFromHeaders(e, "X-Vod-Upload-PSM"),
                    r =
                      (r && (t["X-Vod-Upload-PSM"] = r),
                      rF.getHeaderFromHeaders(e, "X-Vod-Upload-UserID"));
                  return r && (t["X-Vod-Upload-UserID"] = r), t;
                },
                pushEncrypyHeader: function (e, t, r) {
                  t.useGcmEncryptionMode && t.gcmEncryptionMode && r !== rx
                    ? ((e["X-Upload-Server-Gcm-Encryption-Mode"] =
                        t.gcmEncryptionMode),
                      (e["X-Upload-Server-Gcm-Encryption-Key"] =
                        t.encryptionKey))
                    : t.encryptionMode &&
                      ((e["X-Upload-Server-Encryption-Mode"] =
                        t.encryptionMode),
                      (e["X-Upload-Server-Encryption-Key"] = t.encryptionKey));
                },
                minSliceSize: function (e, t) {
                  return !e && t ? 5242880 : 0;
                },
                resolveHeader: function (e) {
                  var t =
                      1 < arguments.length &&
                      void 0 !== arguments[1] &&
                      arguments[1],
                    r = {};
                  return (
                    Array.isArray(e) &&
                      e.forEach(function (e) {
                        var t = null == (t = e.Key) ? void 0 : t.toLowerCase();
                        e.Key && e.Value && (r[t] = e.Value);
                      }),
                    "[object Object]" === Object.prototype.toString.call(e) &&
                      rU(r, e),
                    t &&
                      ((e = rA.find(function (e) {
                        return r.hasOwnProperty(e);
                      }))
                        ? (r[e] = "gateway")
                        : (r["x-storage-mode"] = "gateway")),
                    r
                  );
                },
              };
              function rN(e) {
                return (rN =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              function rH() {
                try {
                  var e = !Boolean.prototype.valueOf.call(
                    Reflect.construct(Boolean, [], function () {})
                  );
                } catch (e) {}
                return (rH = function () {
                  return !!e;
                })();
              }
              function rL(e) {
                return (rL = Object.setPrototypeOf
                  ? Object.getPrototypeOf.bind()
                  : function (e) {
                      return e.__proto__ || Object.getPrototypeOf(e);
                    })(e);
              }
              function rK(e, t) {
                return (rK = Object.setPrototypeOf
                  ? Object.setPrototypeOf.bind()
                  : function (e, t) {
                      return (e.__proto__ = t), e;
                    })(e, t);
              }
              var rq = (() => {
                  var e;
                  function t() {
                    var e, r, i;
                    return (
                      (function (e, t) {
                        if (!(e instanceof t))
                          throw TypeError("Cannot call a class as a function");
                      })(this, t),
                      (((r = rL((r = t))),
                      (e = (function (e, t) {
                        if (t && ("object" == rN(t) || "function" == typeof t))
                          return t;
                        if (void 0 !== t)
                          throw TypeError(
                            "Derived constructors may only return object or undefined"
                          );
                        return (function (e) {
                          if (void 0 === e)
                            throw ReferenceError(
                              "this hasn't been initialised - super() hasn't been called"
                            );
                          return e;
                        })(e);
                      })(
                        this,
                        rH()
                          ? Reflect.construct(r, [], rL(this).constructor)
                          : r.apply(this, i)
                      ))).xhr = new XMLHttpRequest()),
                      (e._data = null),
                      e
                    );
                  }
                  return (
                    (function (e, t) {
                      if ("function" != typeof t && null !== t)
                        throw TypeError(
                          "Super expression must either be null or a function"
                        );
                      (e.prototype = Object.create(t && t.prototype, {
                        constructor: {
                          value: e,
                          writable: !0,
                          configurable: !0,
                        },
                      })),
                        Object.defineProperty(e, "prototype", { writable: !1 }),
                        t && rK(e, t);
                    })(t, u.a),
                    (e = [
                      {
                        key: "_ajax",
                        value: function (e) {
                          var t = this,
                            r = this.xhr;
                          (r.upload.onprogress = function (e) {
                            t.emit("progress", e);
                          }),
                            (r.onreadystatechange = function () {
                              4 === r.readyState &&
                                ((r.upload.onprogress = rF.noop),
                                (r.onreadystatechange = rF.noop),
                                (r.params = e),
                                t._data &&
                                  t._data.url &&
                                  (r.currentUrl = t._data.url),
                                (r.status >= 200 && r.status < 300) ||
                                304 === r.status
                                  ? t.emit("complete", r)
                                  : r.status >= 400 && t.emit("error", r));
                            }),
                            (r.onerror = function () {
                              (r.errText = "unknow net error"),
                                t.emit("error", r);
                            }),
                            (r.ontimeout = function () {
                              (r.errText = "timeout"), t.emit("error", r);
                            }),
                            (r.onabort = function () {
                              (r.errText = "abort"), t.emit("error", r);
                            }),
                            r.send(e);
                        },
                      },
                      {
                        key: "send",
                        value: function (e) {
                          var t = this;
                          return (
                            (this._data = e),
                            this.xhr.open(e.method || "POST", e.url || "", !0),
                            e.headers &&
                              Object.keys(e.headers).forEach(function (r) {
                                t.xhr.setRequestHeader(r, e.headers[r]);
                              }),
                            (this.xhr.timeout = e.timeout || 0),
                            e.ontimeout && (this.xhr.ontimeout = e.ontimeout),
                            e.binary
                              ? this.sendAsBinary(e)
                              : e.custom
                              ? "object" === rN(e.custom)
                                ? this.sendAsCustom(JSON.stringify(e.custom))
                                : "none" === e.custom
                                ? (delete e.custom, this.sendAsCustom())
                                : this.sendAsCustom(e.custom)
                              : this.sendAsFormData(e)
                          );
                        },
                      },
                      {
                        key: "sendAsBinary",
                        value: function (e) {
                          return (
                            this.xhr.setRequestHeader(
                              "Content-Type",
                              "application/octet-stream"
                            ),
                            this.xhr.setRequestHeader(
                              "Content-Disposition",
                              'attachment; filename="'.concat(
                                encodeURI(e.filename),
                                '"'
                              )
                            ),
                            this._ajax(e.file)
                          );
                        },
                      },
                      {
                        key: "sendAsFormData",
                        value: function (e) {
                          t =
                            (t = e.formData
                              ? "function" == typeof e.formData
                                ? e.formData()
                                : e.formData
                              : t) || [];
                          for (
                            var t, r = new FormData(), i = 0, n = t.length;
                            i < n;
                            i++
                          ) {
                            var o = r[i];
                            r.append(o.name, o.value);
                          }
                          return (
                            e.file && r.append(e.field, e.file, e.name),
                            this._ajax(r)
                          );
                        },
                      },
                      {
                        key: "sendAsCustom",
                        value: function (e) {
                          return this._ajax(e);
                        },
                      },
                      {
                        key: "abort",
                        value: function () {
                          (this.xhr.onreadystatechange = rF.noop),
                            this.xhr.abort();
                        },
                      },
                      {
                        key: "getResponse",
                        value: function () {
                          return this.xhr.response;
                        },
                      },
                      {
                        key: "getText",
                        value: function () {
                          return this.xhr.responseText;
                        },
                      },
                      {
                        key: "getJson",
                        value: function () {
                          return JSON.parse(this.xhr.responseText);
                        },
                      },
                    ]),
                    (function (e, t) {
                      for (var r = 0; r < t.length; r++) {
                        var i,
                          n = t[r];
                        (n.enumerable = n.enumerable || !1),
                          (n.configurable = !0),
                          "value" in n && (n.writable = !0),
                          Object.defineProperty(
                            e,
                            ((i = (function (e, t) {
                              if ("object" != rN(e) || !e) return e;
                              var r = e[Symbol.toPrimitive];
                              if (void 0 === r)
                                return ("string" === t ? String : Number)(e);
                              if (
                                ((r = r.call(e, t || "default")),
                                "object" != rN(r))
                              )
                                return r;
                              throw TypeError(
                                "@@toPrimitive must return a primitive value."
                              );
                            })((i = n.key), "string")),
                            "symbol" == rN(i) ? i : i + ""),
                            n
                          );
                      }
                    })(t.prototype, e),
                    Object.defineProperty(t, "prototype", { writable: !1 }),
                    t
                  );
                })(),
                eG = r(1),
                rW = r.n(eG);
              function rV(e) {
                return (rV =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              function rJ(e, t) {
                var r,
                  i = Object.keys(e);
                return (
                  Object.getOwnPropertySymbols &&
                    ((r = Object.getOwnPropertySymbols(e)),
                    t &&
                      (r = r.filter(function (t) {
                        return Object.getOwnPropertyDescriptor(e, t).enumerable;
                      })),
                    i.push.apply(i, r)),
                  i
                );
              }
              function rZ(e) {
                for (var t = 1; t < arguments.length; t++) {
                  var r = null != arguments[t] ? arguments[t] : {};
                  t % 2
                    ? rJ(Object(r), !0).forEach(function (t) {
                        var i, n;
                        (i = t),
                          (n = r[t]),
                          (i = rQ(i)) in e
                            ? Object.defineProperty(e, i, {
                                value: n,
                                enumerable: !0,
                                configurable: !0,
                                writable: !0,
                              })
                            : (e[i] = n);
                      })
                    : Object.getOwnPropertyDescriptors
                    ? Object.defineProperties(
                        e,
                        Object.getOwnPropertyDescriptors(r)
                      )
                    : rJ(Object(r)).forEach(function (t) {
                        Object.defineProperty(
                          e,
                          t,
                          Object.getOwnPropertyDescriptor(r, t)
                        );
                      });
                }
                return e;
              }
              function rX() {
                return (rX = Object.assign
                  ? Object.assign.bind()
                  : function (e) {
                      for (var t = 1; t < arguments.length; t++) {
                        var r,
                          i = arguments[t];
                        for (r in i)
                          ({}).hasOwnProperty.call(i, r) && (e[r] = i[r]);
                      }
                      return e;
                    }).apply(null, arguments);
              }
              function rQ(e) {
                return (
                  (e = (function (e, t) {
                    if ("object" != rV(e) || !e) return e;
                    var r = e[Symbol.toPrimitive];
                    if (void 0 === r)
                      return ("string" === t ? String : Number)(e);
                    if (((r = r.call(e, t || "default")), "object" != rV(r)))
                      return r;
                    throw TypeError(
                      "@@toPrimitive must return a primitive value."
                    );
                  })(e, "string")),
                  "symbol" == rV(e) ? e : e + ""
                );
              }
              function r$() {
                try {
                  var e = !Boolean.prototype.valueOf.call(
                    Reflect.construct(Boolean, [], function () {})
                  );
                } catch (e) {}
                return (r$ = function () {
                  return !!e;
                })();
              }
              function rY(e) {
                return (rY = Object.setPrototypeOf
                  ? Object.getPrototypeOf.bind()
                  : function (e) {
                      return e.__proto__ || Object.getPrototypeOf(e);
                    })(e);
              }
              function r1(e, t) {
                return (r1 = Object.setPrototypeOf
                  ? Object.setPrototypeOf.bind()
                  : function (e, t) {
                      return (e.__proto__ = t), e;
                    })(e, t);
              }
              var r0 = (() => {
                  var e;
                  function t(e, r) {
                    var i, n, o;
                    return (
                      (function (e, t) {
                        if (!(e instanceof t))
                          throw TypeError("Cannot call a class as a function");
                      })(this, t),
                      (((n = rY((n = t))),
                      (i = (function (e, t) {
                        if (t && ("object" == rV(t) || "function" == typeof t))
                          return t;
                        if (void 0 !== t)
                          throw TypeError(
                            "Derived constructors may only return object or undefined"
                          );
                        return (function (e) {
                          if (void 0 === e)
                            throw ReferenceError(
                              "this hasn't been initialised - super() hasn't been called"
                            );
                          return e;
                        })(e);
                      })(
                        this,
                        r$()
                          ? Reflect.construct(n, [], rY(this).constructor)
                          : n.apply(this, o)
                      ))).options = e),
                      (i.config = r),
                      (i.uploaderCtx = e.context),
                      (i.file = e.file),
                      (i.cacheKey = "__bd_uploader_cache"),
                      i
                    );
                  }
                  return (
                    (function (e, t) {
                      if ("function" != typeof t && null !== t)
                        throw TypeError(
                          "Super expression must either be null or a function"
                        );
                      (e.prototype = Object.create(t && t.prototype, {
                        constructor: {
                          value: e,
                          writable: !0,
                          configurable: !0,
                        },
                      })),
                        Object.defineProperty(e, "prototype", { writable: !1 }),
                        t && r1(e, t);
                    })(t, u.a),
                    (e = [
                      {
                        key: "start",
                        value: function (e, t) {
                          (this._st = Date.now()),
                            this.uploaderCtx._broadcast(
                              "startSelectRoute",
                              null,
                              !0
                            ),
                            (this.clientIp = e.clientIp),
                            (this.selectRouteTimeout =
                              e.selectRouteTimeout || 5e3),
                            (this.selectRouteCacheTime =
                              e.selectRouteCacheTime || 36e5),
                            (this.selectRouteFileSize =
                              e.selectRouteFileSize || 0x80000000),
                            (this.completeCallback = t),
                            (e = this.checkSelect({ clientIp: this.clientIp }))
                              ? this.success(e, null, !0)
                              : this.startSelectRoute();
                        },
                      },
                      {
                        key: "checkSelect",
                        value: function (e) {
                          var e = e.clientIp,
                            t = null;
                          try {
                            t = JSON.parse(
                              this.uploaderCtx.storage.getItem(this.cacheKey)
                            );
                          } catch (e) {
                            return null;
                          }
                          if (t) {
                            var r = t.lastClientIp,
                              i = t.lastSelectRouteTime;
                            if (e && e !== r) return null;
                            if (
                              new Date().getTime() - i <
                              this.selectRouteCacheTime
                            )
                              return t;
                          }
                          return null;
                        },
                      },
                      {
                        key: "startSelectRoute",
                        value: function () {
                          var e = this,
                            t = this.config.region,
                            r = new rq(),
                            i =
                              (r.on("complete", function (t) {
                                if (t.response)
                                  try {
                                    var r,
                                      i = JSON.parse(t.response);
                                    i.ResponseMetadata.Error
                                      ? e.fail({
                                          xhr: t,
                                          errorCode:
                                            i.ResponseMetadata.Error.CodeN,
                                          error: i.ResponseMetadata.Error.Code,
                                          message:
                                            i.ResponseMetadata.Error.Message,
                                        })
                                      : ((r = i.Result.Domains), e.race(r, t));
                                  } catch (r) {
                                    e.fail({
                                      error: "catch error: ".concat(
                                        r.toString()
                                      ),
                                      xhr: t,
                                    });
                                  }
                                else
                                  e.fail({
                                    error: "request fail: ".concat(
                                      t.statusText || t.errText || "UNKNOWN"
                                    ),
                                    xhr: t,
                                  });
                              }),
                              r.on("error", function (t) {
                                var r = {
                                  error: "request fail: ".concat(
                                    t.statusText || t.errText || "UNKNOWN"
                                  ),
                                  xhr: t,
                                };
                                t.response &&
                                  (t = JSON.parse(t.response))
                                    .ResponseMetadata &&
                                  t.ResponseMetadata.Error &&
                                  ((r.errorCode =
                                    t.ResponseMetadata.Error.CodeN),
                                  (r.error = t.ResponseMetadata.Error.Code),
                                  (r.message =
                                    t.ResponseMetadata.Error.Message)),
                                  e.fail(r);
                              }),
                              this.config.videoHost),
                            n =
                              this.config.videoConfig &&
                              this.config.videoConfig.spaceName,
                            o = {
                              Action: "GetUploadCandidates",
                              Version: "2020-11-19",
                              SpaceName: (n =
                                this.options.type === rO &&
                                null != (o = this.config.objectConfig) &&
                                o.spaceName
                                  ? null == (o = this.config.objectConfig)
                                    ? void 0
                                    : o.spaceName
                                  : n),
                            },
                            n = this.options.stsToken,
                            s = rF.toQueryString(o),
                            a = n.AccessKeyID,
                            c = n.AccessKeyId,
                            u = n.SecretAccessKey,
                            l = n.SessionToken,
                            n = n.CurrentTime,
                            i = {
                              method: "GET",
                              url: "".concat(i, "?").concat(s),
                              timeout: this.config.gatewayTimeout,
                              region: t,
                              params: o,
                            },
                            s = new rW.a(i, "vod"),
                            t =
                              (this.config.useServerCurrentTime &&
                                Math.abs(new Date(n) - new Date()) > 6e4 &&
                                (this.systemTimeGap = new Date(n) - new Date()),
                              this.systemTimeGap
                                ? new Date(
                                    new Date().getTime() + this.systemTimeGap
                                  )
                                : new Date());
                          s.addAuthorization(
                            {
                              accessKeyId: c || a,
                              secretAccessKey: u,
                              sessionToken: l,
                            },
                            t
                          ),
                            r.send(i);
                        },
                      },
                      {
                        key: "race",
                        value: function (e, t) {
                          var r = this,
                            i = this.file,
                            n = (i.slice || i.webkitSlice || i.mozSlice).call(
                              i,
                              0,
                              Math.min(this.selectRouteFileSize, i.size)
                            ),
                            o = e.map(function (e) {
                              return {
                                domainName: e.Name,
                                domainInfo: e,
                                percent: 0,
                                startTime: new Date().getTime(),
                                endTime: new Date().getTime(),
                                complete: !1,
                              };
                            }),
                            s = 0,
                            a = o.length;
                          o.forEach(function (e, i) {
                            var n = new rq();
                            n.on("complete", function () {
                              (o[i].endTime = new Date().getTime()),
                                (o[i].complete = !0),
                                o.forEach(function (e, t) {
                                  i !== t && e.transport && e.transport.abort();
                                }),
                                r.formatRaceInfo(o, t);
                            }),
                              n.on("error", function (e) {
                                (o[i].endTime = new Date().getTime()),
                                  (o[i].complete = !0),
                                  (o[i].error = e.errText),
                                  a <= ++s && r.formatRaceInfo(o, t);
                              }),
                              n.on("progress", function (e) {
                                (e = e.loaded / e.total), (o[i].percent = e);
                              }),
                              (o[i].transport = n);
                          }),
                            o.forEach(function (e) {
                              var t = e.domainInfo,
                                i = {
                                  oid: t.StoreID,
                                  tosDomain: ""
                                    .concat(r.config.schema, "://")
                                    .concat(t.Name),
                                },
                                i = "".concat(
                                  rF.urlTemplate(f, i),
                                  "?speedtest"
                                ),
                                t = t.Sign;
                              e.transport.send({
                                method: "post",
                                url: i,
                                headers: {
                                  Authorization: t,
                                  "Content-CRC32": "ignore",
                                },
                                file: n,
                                binary: 1,
                                timeout: r.selectRouteTimeout,
                              });
                            });
                        },
                      },
                      {
                        key: "formatRaceInfo",
                        value: function (e, t) {
                          e.sort(function (e, t) {
                            return e.percent < t.percent
                              ? 1
                              : t.percent < e.percent
                              ? -1
                              : e.error
                              ? 1
                              : t.error
                              ? -1
                              : 0;
                          }),
                            e.forEach(function (e) {
                              delete e.transport;
                            }),
                            (e = {
                              lastClientIp: this.clientIp,
                              lastSelectRouteTime: new Date().getTime(),
                              raceInfo: e,
                              type: "success",
                            }),
                            this.uploaderCtx.storage.setItem(
                              this.cacheKey,
                              JSON.stringify(e)
                            ),
                            this.success(e, t);
                        },
                      },
                      {
                        key: "success",
                        value: function (e, t) {
                          var r =
                              2 < arguments.length &&
                              void 0 !== arguments[2] &&
                              arguments[2],
                            t = t && this.formatXhr(t);
                          this.uploaderCtx.logger.send(
                            rX(
                              rZ(
                                rZ(
                                  {
                                    stage: "selectRoute",
                                    stageStartTime: this._st,
                                    stageEndTime: Date.now(),
                                    duration: Date.now() - this._st,
                                    fileSize: this.file && this.file.size,
                                  },
                                  t
                                ),
                                {},
                                { useCache: r }
                              ),
                              e
                            )
                          ),
                            this.uploaderCtx._broadcast(
                              "completeSelectRoute",
                              rZ(rZ({}, e), {}, { useCache: r }),
                              !0
                            ),
                            this.completeCallback({
                              selectRouteResult: e.raceInfo,
                            });
                        },
                      },
                      {
                        key: "fail",
                        value: function (e) {
                          var t = {
                            error: e.error,
                            errorCode: e.errorCode,
                            message: e.message,
                          };
                          this.uploaderCtx.logger.send(
                            rX(
                              rZ(
                                {
                                  stage: "selectRoute",
                                  stageStartTime: this._st,
                                  stageEndTime: Date.now(),
                                  duration: Date.now() - this._st,
                                  fileSize: this.file && this.file.size,
                                  extra: t,
                                  type: "warn",
                                },
                                this.formatXhr(e.xhr)
                              )
                            )
                          ),
                            this.uploaderCtx._broadcast(
                              "completeSelectRoute",
                              rZ({ type: "warn" }, t),
                              !0
                            ),
                            this.completeCallback();
                        },
                      },
                      {
                        key: "formatXhr",
                        value: function (e) {
                          return {
                            req: { url: e.currentUrl, param: e.params },
                            res: {
                              status: e.status,
                              header: e.getAllResponseHeaders(),
                              body: e.responseText,
                            },
                          };
                        },
                      },
                    ]),
                    (function (e, t) {
                      for (var r = 0; r < t.length; r++) {
                        var i = t[r];
                        (i.enumerable = i.enumerable || !1),
                          (i.configurable = !0),
                          "value" in i && (i.writable = !0),
                          Object.defineProperty(e, rQ(i.key), i);
                      }
                    })(t.prototype, e),
                    Object.defineProperty(t, "prototype", { writable: !1 }),
                    t
                  );
                })(),
                r2 = {
                  crc32: function (e, t) {
                    for (
                      var r = [
                          0, 0x77073096, 0xee0e612c, 0x990951ba, 0x76dc419,
                          0x706af48f, 0xe963a535, 0x9e6495a3, 0xedb8832,
                          0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x9b64c2b,
                          0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064,
                          0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d,
                          0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856,
                          0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f,
                          0x63066cd9, 0xfa0f3d63, 0x8d080df5, 0x3b6e20c8,
                          0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1,
                          0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa,
                          0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3,
                          0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac,
                          0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5,
                          0x56b3c423, 0xcfba9599, 0xb8bda50f, 0x2802b89e,
                          0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87,
                          0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190,
                          0x1db7106, 0x98d220bc, 0xefd5102a, 0x71b18589,
                          0x6b6b51f, 0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2,
                          0xf00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb,
                          0x86d3d2d, 0x91646c97, 0xe6635c01, 0x6b6b51f4,
                          0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed,
                          0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6,
                          0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf,
                          0x15da2d49, 0x8cd37cf3, 0xfbd44c65, 0x4db26158,
                          0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541,
                          0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a,
                          0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73,
                          0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c,
                          0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525,
                          0x206f85b3, 0xb966d409, 0xce61e49f, 0x5edef90e,
                          0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17,
                          0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320,
                          0x9abfb3b6, 0x3b6e20c, 0x74b1d29a, 0xead54739,
                          0x9dd277af, 0x4db2615, 0x73dc1683, 0xe3630b12,
                          0x94643b84, 0xd6d6a3e, 0x7a6a5aa8, 0xe40ecf0b,
                          0x9309ff9d, 0xa00ae27, 0x7d079eb1, 0xf00f9344,
                          0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d,
                          0x806567cb, 0x196c3671, 0x6e6b06e7, 0xfed41b76,
                          0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f,
                          0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8,
                          0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1,
                          0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda,
                          0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3,
                          0xa867df55, 0x316e8eef, 0x4669be79, 0xcb61b38c,
                          0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795,
                          0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe,
                          0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7,
                          0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0,
                          0xec63f226, 0x756aa39c, 0x26d930a, 0x9c0906a9,
                          0xeb0e363f, 0x72076785, 0x5005713, 0x95bf4a82,
                          0xe2b87a14, 0x7bb12bae, 0xcb61b38, 0x92d28e9b,
                          0xe5d5be0d, 0x7cdcefb7, 0xbdbdf21, 0x86d3d2d4,
                          0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd,
                          0xf6b9265b, 0x6fb077e1, 0x18b74777, 0x88085ae6,
                          0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff,
                          0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278,
                          0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661,
                          0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a,
                          0xd9d65adc, 0x40df0b66, 936918e3, 0xa9bcae53,
                          0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9, 0xbdbdf21c,
                          0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605,
                          0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e,
                          0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37,
                          0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
                        ],
                        i =
                          ("undefined" != typeof Int32Array &&
                            (r = new Int32Array(r)),
                          -1 ^ ~~t),
                        n = (e = new Uint8Array(e)).length,
                        o = 0;
                      o < n;
                      o++
                    )
                      i = r[255 & (i ^ e[o])] ^ (i >>> 8);
                    return (-1 ^ i) >>> 0;
                  },
                  dec2hex: function (e) {
                    if (void 0 !== e)
                      return (function e(t) {
                        return t.length < 8 ? e((t = "0".concat(t))) : t;
                      })(Number(e).toString(16));
                  },
                };
              function r4(e) {
                return (r4 =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              var r3 =
                  ((o = function e(t, r, i, n) {
                    (function (e, t) {
                      if (!(e instanceof t))
                        throw TypeError("Cannot call a class as a function");
                    })(this, e),
                      (this.file = t),
                      (this.successProcess = i),
                      (this.failProcess = n),
                      (this.sliceLength = r),
                      (this.retryTime = 0),
                      (this.fileSize = t.size),
                      (this.crc32Array = []);
                  }),
                  (s = [
                    {
                      key: "start",
                      value: function () {
                        this.readFileCrc32(this.file);
                      },
                    },
                    {
                      key: "readFileCrc32",
                      value: function (e) {
                        var t = this,
                          r = this.sliceLength,
                          i = e.slice || e.webkitSlice || e.mozSlice,
                          n = new FileReader(),
                          o = 0,
                          s = 0,
                          a = 0,
                          c = Math.max(r, 5242880),
                          u = function () {
                            s < e.size &&
                              ((s = Math.min(o + r, e.size)),
                              e.size - s <= c) &&
                              (s = e.size),
                              n.readAsArrayBuffer(i.call(e, o, s)),
                              (n.onload = function (r) {
                                (r = r.target.result),
                                  (a = r2.crc32(r, 0)),
                                  t.crc32Array.push({
                                    start: o,
                                    end: s,
                                    crc32: r2.dec2hex(a),
                                    buffer: r,
                                  }),
                                  (o = s) < e.size
                                    ? u()
                                    : t.success(t.crc32Array);
                              });
                          };
                        u();
                      },
                    },
                    {
                      key: "success",
                      value: function (e) {
                        this.successProcess(e);
                      },
                    },
                    {
                      key: "fail",
                      value: function (e, t, r, i) {
                        3 <= this.retryTime
                          ? this.failProcess()
                          : (this.readFileCrc32(e, t, r, i), this.retryTime++);
                      },
                    },
                  ]),
                  (function (e, t) {
                    for (var r = 0; r < t.length; r++) {
                      var i,
                        n = t[r];
                      (n.enumerable = n.enumerable || !1),
                        (n.configurable = !0),
                        "value" in n && (n.writable = !0),
                        Object.defineProperty(
                          e,
                          ((i = (function (e, t) {
                            if ("object" != r4(e) || !e) return e;
                            var r = e[Symbol.toPrimitive];
                            if (void 0 === r)
                              return ("string" === t ? String : Number)(e);
                            if (
                              ((r = r.call(e, t || "default")),
                              "object" != r4(r))
                            )
                              return r;
                            throw TypeError(
                              "@@toPrimitive must return a primitive value."
                            );
                          })((i = n.key), "string")),
                          "symbol" == r4(i) ? i : i + ""),
                          n
                        );
                    }
                  })(o.prototype, s),
                  Object.defineProperty(o, "prototype", { writable: !1 }),
                  o),
                r5 = "The format of stsToken is incorrect.";
              function r6(e) {
                return (r6 =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              function r8() {
                return (r8 = Object.assign
                  ? Object.assign.bind()
                  : function (e) {
                      for (var t = 1; t < arguments.length; t++) {
                        var r,
                          i = arguments[t];
                        for (r in i)
                          ({}).hasOwnProperty.call(i, r) && (e[r] = i[r]);
                      }
                      return e;
                    }).apply(null, arguments);
              }
              function r9(e, t) {
                (null == t || t > e.length) && (t = e.length);
                for (var r = 0, i = Array(t); r < t; r++) i[r] = e[r];
                return i;
              }
              var r7 =
                  ((a = function e(t) {
                    var r,
                      i =
                        1 < arguments.length && void 0 !== arguments[1]
                          ? arguments[1]
                          : {};
                    (function (e, t) {
                      if (!(e instanceof t))
                        throw TypeError("Cannot call a class as a function");
                    })(this, e),
                      (this.context = t.context),
                      (this.key = t.key),
                      (this.isDirect = t.isDirect),
                      (this.isImageBatchUpload = t.isImageBatchUpload),
                      (this.file = t.file),
                      (this.type =
                        (this.isImageBatchUpload
                          ? null == (r = this.file[0])
                            ? void 0
                            : r.type
                          : null == (r = this.file)
                          ? void 0
                          : r.type) || ""),
                      (this.sliceLength = t.sliceSize),
                      (this.config = i);
                  }),
                  (c = [
                    {
                      key: "start",
                      value: function (e, t, r) {
                        (this.successProcess = t),
                          (this.failProcess = r),
                          (this._st = Date.now()),
                          this.crc32(this.file, this.sliceLength);
                      },
                    },
                    {
                      key: "crc32",
                      value: function (e, t) {
                        var r = this;
                        if (this.isImageBatchUpload)
                          for (
                            var i = e.length,
                              n = [],
                              o = function (t) {
                                new r3(
                                  e[t],
                                  e[t].size,
                                  function (e) {
                                    (n[t] = e[0]),
                                      n.filter(function (e) {
                                        return !!e;
                                      }).length === i && r.success(n);
                                  },
                                  function (e) {
                                    r.fail(e);
                                  }
                                ).start();
                              },
                              s = 0;
                            s < i;
                            s++
                          )
                            o(s);
                        else
                          e && e.size && !(e.size <= 0)
                            ? this.isDirect
                              ? new r3(
                                  e,
                                  e.size,
                                  function (e) {
                                    r.success(e);
                                  },
                                  function (e) {
                                    r.fail({
                                      errorCode: 1000003,
                                      message: "get crc32 error: ".concat(
                                        e && e.message
                                      ),
                                    });
                                  }
                                ).start()
                              : this.sliceFile(
                                  e,
                                  t,
                                  function (e) {
                                    r.success(e);
                                  },
                                  function (e) {
                                    r.fail(e);
                                  }
                                )
                            : this.fail({
                                errorCode: 1000003,
                                message:
                                  "There is a problem with the input file or fileSize.",
                              });
                      },
                    },
                    {
                      key: "sliceFile",
                      value: function (e, t, r, i) {
                        for (
                          var n = [],
                            o = e.size,
                            s = e.slice || e.webkitSlice || e.mozSlice,
                            a = 0,
                            c = 0,
                            u = 0,
                            l = Math.max(5242880, t);
                          c < o;

                        )
                          (c = Math.min(a + t, o)),
                            n.push({
                              start: a,
                              end: (c = o - c <= l ? o : c),
                              crc32: 0,
                            }),
                            (a = c);
                        try {
                          !(function t(a) {
                            var c = new FileReader(),
                              l = n[a].start,
                              f = n[a].end;
                            c.readAsArrayBuffer(s.call(e, l, f)),
                              (c.onload = function (e) {
                                (e = e.target.result),
                                  (u = r2.dec2hex(r2.crc32(e, 0))),
                                  (n[a].crc32 = u),
                                  f === o ? r(n) : t(n.length - 1);
                              }),
                              (c.onerror = function (e) {
                                var t = e.target.error.name,
                                  e = e.target.error.message;
                                i({
                                  crc32Array: n,
                                  errorCode: 1000003,
                                  message: "".concat(t, ": ").concat(e),
                                });
                              });
                          })(0);
                        } catch (e) {
                          i({ message: e && e.toString() });
                        }
                      },
                    },
                    {
                      key: "getCrc32Key",
                      value: function (e, t) {
                        var r;
                        return (
                          (t =
                            "[object Array]" ===
                            Object.prototype.toString.call(t)
                              ? (function (e) {
                                  if (Array.isArray(e)) return r9(e);
                                })((r = t)) ||
                                (function (e) {
                                  if (
                                    ("undefined" != typeof Symbol &&
                                      null != e[Symbol.iterator]) ||
                                    null != e["@@iterator"]
                                  )
                                    return Array.from(e);
                                })(r) ||
                                (function (e, t) {
                                  var r;
                                  if (e)
                                    return "string" == typeof e
                                      ? r9(e, void 0)
                                      : "Map" ===
                                          (r =
                                            "Object" ===
                                              (r = {}.toString
                                                .call(e)
                                                .slice(8, -1)) && e.constructor
                                              ? e.constructor.name
                                              : r) || "Set" === r
                                      ? Array.from(e)
                                      : "Arguments" === r ||
                                        /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(
                                          r
                                        )
                                      ? r9(e, void 0)
                                      : void 0;
                                })(r) ||
                                (function () {
                                  throw TypeError(
                                    "Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."
                                  );
                                })()
                              : [t]).push(e[0].crc32, e[e.length - 1].crc32),
                          this.config.instanceId &&
                            t.push(this.config.instanceId),
                          t.join("_")
                        );
                      },
                    },
                    {
                      key: "success",
                      value: function (e) {
                        var t = this.context,
                          r = this.key,
                          i = [],
                          n = [];
                        if (this.isImageBatchUpload)
                          for (var o = 0; o < this.file.length; o++)
                            i.push(this.file[o].size),
                              n.push(this.file[o].name);
                        else (i = this.file.size), (n = this.file.name);
                        var s = this.getCrc32Key(e, i),
                          t = t.tasks[r];
                        t &&
                          this.successProcess(
                            r8(t, {
                              key: r,
                              crc32Array: e,
                              crc32Key: s,
                              sdkVersion: "2.1.3",
                              sliceLength: this.sliceLength,
                              extra: { message: "get crc32 success" },
                              stage: "crc32",
                              type: "success",
                              fileSize: i,
                              fileName: n,
                              stageStartTime: this._st,
                              stageEndTime: Date.now(),
                              duration: Date.now() - this._st,
                              totalDuration: Date.now() - this._st,
                              isDirect: this.isDirect,
                              isImageBatchUpload: this.isImageBatchUpload,
                            })
                          );
                      },
                    },
                    {
                      key: "fail",
                      value: function (e) {
                        var t = this.context,
                          r = this.key,
                          i = e && e.message ? e.message : "get crc32 error",
                          n = e && e.errorCode,
                          e = e && e.crc32Array,
                          t = r8(t.tasks[r], {
                            crc32Array: e,
                            extra: { message: i, errorCode: n },
                            type: "error",
                            stage: "crc32",
                            stageStartTime: this._st,
                            stageEndTime: Date.now(),
                            duration: Date.now() - this._st,
                            totalDuration: Date.now() - this._st,
                          });
                        this.failProcess(t);
                      },
                    },
                  ]),
                  (function (e, t) {
                    for (var r = 0; r < t.length; r++) {
                      var i,
                        n = t[r];
                      (n.enumerable = n.enumerable || !1),
                        (n.configurable = !0),
                        "value" in n && (n.writable = !0),
                        Object.defineProperty(
                          e,
                          ((i = (function (e, t) {
                            if ("object" != r6(e) || !e) return e;
                            var r = e[Symbol.toPrimitive];
                            if (void 0 === r)
                              return ("string" === t ? String : Number)(e);
                            if (
                              ((r = r.call(e, t || "default")),
                              "object" != r6(r))
                            )
                              return r;
                            throw TypeError(
                              "@@toPrimitive must return a primitive value."
                            );
                          })((i = n.key), "string")),
                          "symbol" == r6(i) ? i : i + ""),
                          n
                        );
                    }
                  })(a.prototype, c),
                  Object.defineProperty(a, "prototype", { writable: !1 }),
                  a),
                ie = {
                  checkStsToken: function (e) {
                    return (
                      !e ||
                      (e.SessionToken &&
                        e.SecretAccessKey &&
                        (e.AccessKeyId || e.AccessKeyID))
                    );
                  },
                  checkIfGateway: function (e) {
                    return (
                      !!e &&
                      !!rA.find(function (t) {
                        return e.hasOwnProperty(t);
                      })
                    );
                  },
                  checkServiceName: function (e, t, r) {
                    if ("vod" === r || r === rT) return r;
                    if (e !== rx) {
                      if (e === rE) return rT;
                      if (e === rO) {
                        if (t.objectConfig && t.objectConfig.spaceName)
                          return "vod";
                        if (t.objectConfig && t.objectConfig.serviceId)
                          return rT;
                        if (t.videoConfig && t.videoConfig.spaceName)
                          return "vod";
                        if (t.imageConfig && t.imageConfig.serviceId) return rT;
                      }
                    }
                    return "vod";
                  },
                };
              function it(e) {
                return (it =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              function ir(e, t) {
                var r,
                  i = Object.keys(e);
                return (
                  Object.getOwnPropertySymbols &&
                    ((r = Object.getOwnPropertySymbols(e)),
                    t &&
                      (r = r.filter(function (t) {
                        return Object.getOwnPropertyDescriptor(e, t).enumerable;
                      })),
                    i.push.apply(i, r)),
                  i
                );
              }
              function ii() {
                return (ii = Object.assign
                  ? Object.assign.bind()
                  : function (e) {
                      for (var t = 1; t < arguments.length; t++) {
                        var r,
                          i = arguments[t];
                        for (r in i)
                          ({}).hasOwnProperty.call(i, r) && (e[r] = i[r]);
                      }
                      return e;
                    }).apply(null, arguments);
              }
              function io(e) {
                return (
                  (e = (function (e, t) {
                    if ("object" != it(e) || !e) return e;
                    var r = e[Symbol.toPrimitive];
                    if (void 0 === r)
                      return ("string" === t ? String : Number)(e);
                    if (((r = r.call(e, t || "default")), "object" != it(r)))
                      return r;
                    throw TypeError(
                      "@@toPrimitive must return a primitive value."
                    );
                  })(e, "string")),
                  "symbol" == it(e) ? e : e + ""
                );
              }
              function is() {
                try {
                  var e = !Boolean.prototype.valueOf.call(
                    Reflect.construct(Boolean, [], function () {})
                  );
                } catch (e) {}
                return (is = function () {
                  return !!e;
                })();
              }
              function ia(e) {
                return (ia = Object.setPrototypeOf
                  ? Object.getPrototypeOf.bind()
                  : function (e) {
                      return e.__proto__ || Object.getPrototypeOf(e);
                    })(e);
              }
              function ic(e, t) {
                return (ic = Object.setPrototypeOf
                  ? Object.setPrototypeOf.bind()
                  : function (e, t) {
                      return (e.__proto__ = t), e;
                    })(e, t);
              }
              var iu = (() => {
                var e;
                function t(e, r) {
                  var i, n, o;
                  return (
                    (function (e, t) {
                      if (!(e instanceof t))
                        throw TypeError("Cannot call a class as a function");
                    })(this, t),
                    (((n = ia((n = t))),
                    (i = (function (e, t) {
                      if (t && ("object" == it(t) || "function" == typeof t))
                        return t;
                      if (void 0 !== t)
                        throw TypeError(
                          "Derived constructors may only return object or undefined"
                        );
                      return (function (e) {
                        if (void 0 === e)
                          throw ReferenceError(
                            "this hasn't been initialised - super() hasn't been called"
                          );
                        return e;
                      })(e);
                    })(
                      this,
                      is()
                        ? Reflect.construct(n, [], ia(this).constructor)
                        : n.apply(this, o)
                    ))).options = e),
                    (i.config = r),
                    (i.uploaderCtx = e.context),
                    (i.currFileCtx = e.context.tasks[e.key]),
                    (i.systemTimeGap = 0),
                    (i.retryTime = r.retryTaskTime),
                    (i.hasRetryTime = 0),
                    (i.isImageBatchUpload = !!i.options.isImageBatchUpload),
                    (i.isDirect = i.options.isDirect),
                    (i.serviceName = ie.checkServiceName(
                      i.options.type,
                      i.config,
                      i.options.serviceType
                    )),
                    i
                  );
                }
                return (
                  (function (e, t) {
                    if ("function" != typeof t && null !== t)
                      throw TypeError(
                        "Super expression must either be null or a function"
                      );
                    (e.prototype = Object.create(t && t.prototype, {
                      constructor: { value: e, writable: !0, configurable: !0 },
                    })),
                      Object.defineProperty(e, "prototype", { writable: !1 }),
                      t && ic(e, t);
                  })(t, u.a),
                  (e = [
                    {
                      key: "start",
                      value: function (e, t, r) {
                        (this.startOptions = e),
                          (this.failProcess = r),
                          (this.successProcess = t),
                          (this._st = Date.now()),
                          (r = (e = this.uploaderCtx._getCache(
                            this.currFileCtx.crc32Key
                          ))
                            ? JSON.parse(e)
                            : {}),
                          !this.isDirect && r.oid && r.UploadID
                            ? this.resumeFromCache(r)
                            : this.startPreUpload();
                      },
                    },
                    {
                      key: "startPreUpload",
                      value: function () {
                        var e = this,
                          t = this.config.region,
                          r = new rq(),
                          i =
                            (r.on("complete", function (t) {
                              e.success(t);
                            }),
                            r.on("error", function (t) {
                              e.handleError(t);
                            }),
                            ""),
                          n = {},
                          o = this.uploaderCtx.useBackupDomain,
                          s = ie.checkServiceName(
                            this.options.type,
                            this.config,
                            this.options.serviceType
                          ),
                          n =
                            s === rT
                              ? ((i = o
                                  ? this.config.imageFallbackHost
                                  : this.config.imageHost),
                                this.createImageXParams())
                              : ((i = o
                                  ? this.config.videoFallbackHost
                                  : this.config.videoHost),
                                this.createVodParams()),
                          o =
                            (this.currFileCtx.fileSize &&
                              !this.currFileCtx.isImageBatchUpload &&
                              (n.FileSize = this.currFileCtx.fileSize),
                            this.config.useFileExtension &&
                              this.currFileCtx.fileName &&
                              (this.options.type === rO ||
                                this.options.type === rE) &&
                              ((o = this.currFileCtx.fileName),
                              (o = rF.getFileSuffix(o))) &&
                              (n.FileExtension = o),
                            this.options.fileExtension &&
                              (n.FileExtension = this.options.fileExtension),
                            this.config.accountId &&
                              (n["X-Account-Id"] = this.config.accountId),
                            this.currFileCtx.useGcmEncryptionMode &&
                              (n.OpenGcmEnc = !0),
                            this.options.type !== rx &&
                              this.config.bizType &&
                              ((n.BizType = this.config.bizType),
                              (n.AppID = this.config.appId),
                              (n.UserID = this.config.userId)),
                            this.config.openExperiment &&
                              ((n.app_id = this.config.appId),
                              (n.user_id = this.config.userId)),
                            (n.s = Math.random().toString(36).substring(2)),
                            this.options.fileSize &&
                              (n.FileSize = this.options.fileSize),
                            this.currFileCtx.proxyStsToken ||
                              this.config.stsToken),
                          a = rF.toQueryString(n),
                          c = o.AccessKeyID,
                          u = o.AccessKeyId,
                          l = o.SecretAccessKey,
                          f = o.SessionToken,
                          o = o.CurrentTime,
                          h = rF.getDYAddHeader(
                            this.currFileCtx.headers || this.config.headers
                          ),
                          a = {
                            method: "GET",
                            url: "".concat(i, "?").concat(a),
                            timeout: this.config.gatewayTimeout || 0,
                            headers: h,
                            region: t,
                            params: n,
                            pathname: rF.getPathByURL(i),
                          },
                          h = new rW.a(a, s),
                          t =
                            (this.config.useServerCurrentTime &&
                              Math.abs(new Date(o) - new Date()) > 6e4 &&
                              (this.systemTimeGap = new Date(o) - new Date()),
                            this.systemTimeGap
                              ? new Date(
                                  new Date().getTime() + this.systemTimeGap
                                )
                              : new Date());
                        h.addAuthorization(
                          {
                            accessKeyId: u || c,
                            secretAccessKey: l,
                            sessionToken: f,
                          },
                          t
                        ),
                          r.send(a);
                      },
                    },
                    {
                      key: "createImageXParams",
                      value: function () {
                        var e,
                          t = {
                            Action: "ApplyImageUpload",
                            Version: "2018-08-01",
                          };
                        return (
                          this.options.type === rE &&
                            (this.currFileCtx.serviceId ||
                            (this.config.imageConfig &&
                              this.config.imageConfig.serviceId)
                              ? (t.ServiceId =
                                  this.currFileCtx.serviceId ||
                                  this.config.imageConfig.serviceId)
                              : (t.SpaceName =
                                  this.config.videoConfig &&
                                  this.config.videoConfig.spaceName)),
                          this.options.type === rO &&
                            (t.ServiceId =
                              this.currFileCtx.serviceId ||
                              (this.config.objectConfig &&
                                this.config.objectConfig.serviceId) ||
                              (this.config.imageConfig &&
                                this.config.imageConfig.serviceId)),
                          this.currFileCtx.fileSize &&
                            1 < this.currFileCtx.fileSize.length &&
                            (t.UploadNum = this.currFileCtx.fileSize.length),
                          this.options.storeKey &&
                            ((e = this.options.storeKey),
                            "[object Array]" ===
                            Object.prototype.toString.call(e)
                              ? (t.StoreKeys = e)
                              : "[object String]" ===
                                  Object.prototype.toString.call(e) &&
                                (t.StoreKeys = [e])),
                          (t.NeedFallback = !0),
                          t
                        );
                      },
                    },
                    {
                      key: "createVodParams",
                      value: function () {
                        var e =
                            this.config.videoConfig &&
                            this.config.videoConfig.spaceName,
                          t = {
                            Action: "ApplyUploadInner",
                            Version: "2020-11-19",
                            SpaceName: (e =
                              this.options.type === rO &&
                              null != (t = this.config.objectConfig) &&
                              t.spaceName
                                ? null == (t = this.config.objectConfig)
                                  ? void 0
                                  : t.spaceName
                                : e),
                            FileType: this.options.type,
                            IsInner: 1,
                          };
                        return (
                          this.config.enOID && (t.EnOID = 1),
                          (this.options.testHost || this.config.testHost) &&
                            (t.TestHost =
                              this.options.testHost || this.config.testHost),
                          this.startOptions &&
                            this.startOptions.selectRouteResult &&
                            ((e = this.startOptions.selectRouteResult),
                            (t.ClientBestHosts = e
                              .map(function (e) {
                                return e.domainName;
                              })
                              .join(","))),
                          (t.NeedFallback = !0),
                          t
                        );
                      },
                    },
                    {
                      key: "resumeFromCache",
                      value: function (e) {
                        var t = this,
                          r = this.options.key,
                          i = new rq(),
                          n =
                            (i.on("complete", function (i) {
                              var n = null;
                              try {
                                var o = JSON.parse(i.response);
                                if (
                                  !(
                                    2e3 === o.code && 0 < o.data.partlist.length
                                  )
                                )
                                  return t.startPreUpload();
                                var s = t.confirmCache(o.data.partlist),
                                  a = e.hasMerge ? 5 : s.isAllFinished ? 4 : 3,
                                  n = ii(t.currFileCtx, e, {
                                    key: r,
                                    xhr: i,
                                    extra: {
                                      message:
                                        "prepare upload from cache success",
                                    },
                                    stage: "preUpload",
                                    type: "success",
                                    percent: 0,
                                    cacheTask: a,
                                    proxyStsToken: t.options.stsToken,
                                    currentTask: 1,
                                    status: 1,
                                    isBreak: 1,
                                    crc32Array: s.crc32Array,
                                    stageStartTime: t._st,
                                    stageEndTime: Date.now(),
                                    duration: Date.now() - t._st,
                                    totalDuration:
                                      Date.now() -
                                      t._st +
                                      t.currFileCtx.totalDuration,
                                  });
                              } catch (e) {
                                return t.startPreUpload();
                              }
                              t.successProcess(n);
                            }),
                            i.on("error", function (e) {
                              e.status >= 400
                                ? t.startPreUpload()
                                : t.fail({ error: "request error", xhr: e });
                            }),
                            this.config.userId);
                        i.send({
                          method: "get",
                          url: rF.urlTemplate(
                            "{tosDomain}/upload/v1/{oid}?uploadid={uploadId}&action=part_list",
                            {
                              tosDomain: e.tosDomain,
                              oid: e.oid,
                              uploadId: e.UploadID,
                            }
                          ),
                          headers: (function (e) {
                            for (var t = 1; t < arguments.length; t++) {
                              var r = null != arguments[t] ? arguments[t] : {};
                              t % 2
                                ? ir(Object(r), !0).forEach(function (t) {
                                    var i, n;
                                    (i = t),
                                      (n = r[t]),
                                      (i = io(i)) in e
                                        ? Object.defineProperty(e, i, {
                                            value: n,
                                            enumerable: !0,
                                            configurable: !0,
                                            writable: !0,
                                          })
                                        : (e[i] = n);
                                  })
                                : Object.getOwnPropertyDescriptors
                                ? Object.defineProperties(
                                    e,
                                    Object.getOwnPropertyDescriptors(r)
                                  )
                                : ir(Object(r)).forEach(function (t) {
                                    Object.defineProperty(
                                      e,
                                      t,
                                      Object.getOwnPropertyDescriptor(r, t)
                                    );
                                  });
                            }
                            return e;
                          })(
                            {
                              Authorization: e.signature,
                              "X-Storage-U": encodeURIComponent(n),
                            },
                            e.UploadHeader
                          ),
                          timeout: 3e4,
                        });
                      },
                    },
                    {
                      key: "confirmCache",
                      value: function (e) {
                        var t = this.currFileCtx.crc32Array,
                          r = {},
                          i =
                            (e.forEach(function (e) {
                              void 0 === r[e.num - 1] &&
                                (r[e.num - 1] = { tag: !0, crc32: e.crc32 });
                            }),
                            !0),
                          e = t.map(function (e, t) {
                            return (
                              r[t] && r[t].tag && r[t].crc32
                                ? ((e.crc32 = r[t].crc32),
                                  (e.finished = !0),
                                  (e.loaded = e.end - e.start))
                                : (i = !1),
                              e
                            );
                          });
                        return { isAllFinished: i, crc32Array: e };
                      },
                    },
                    {
                      key: "handleError",
                      value: function (e) {
                        if (
                          ((this.options.type === rE &&
                            this.config.imageFallbackHost) ||
                            (this.options.type === rx &&
                              this.config.videoFallbackHost)) &&
                          !this.uploaderCtx.useBackupDomain
                        )
                          this.hasRetryTime < this.retryTime - 1
                            ? this.hasRetryTime++
                            : (this.uploaderCtx.useBackupDomain = !0),
                            this.startPreUpload();
                        else {
                          var t = {
                            error: "request fail: ".concat(
                              e.statusText || e.errText || "UNKNOWN"
                            ),
                            xhr: e,
                          };
                          if (e.response)
                            try {
                              var r = JSON.parse(e.response);
                              r.ResponseMetadata &&
                                r.ResponseMetadata.Error &&
                                ((t.errorCode = r.ResponseMetadata.Error.CodeN),
                                (t.error = r.ResponseMetadata.Error.Code),
                                (t.message = r.ResponseMetadata.Error.Message));
                            } catch (r) {
                              (t.error = e.response.toString()),
                                (t.message = e.response.toString());
                            }
                          this.fail(t);
                        }
                      },
                    },
                    {
                      key: "success",
                      value: function (e) {
                        if (e.response) {
                          var t = null;
                          try {
                            var r = JSON.parse(e.response);
                            if (r.ResponseMetadata.Error)
                              return this.fail({
                                xhr: e,
                                errorCode: r.ResponseMetadata.Error.CodeN,
                                error: r.ResponseMetadata.Error.Code,
                                message: r.ResponseMetadata.Error.Message,
                              });
                            var i,
                              n,
                              o,
                              s,
                              a,
                              c,
                              u,
                              l,
                              f,
                              h,
                              d = this.serviceName,
                              p = r.Result,
                              g =
                                d === rT
                                  ? p.UploadAddress
                                  : p.InnerUploadAddress.UploadNodes[0],
                              m = g.StoreInfos,
                              y = g.SessionKey,
                              _ = g.UploadHeader,
                              b = void 0 === _ ? {} : _,
                              v = d === rT ? g.UploadHosts[0] : g.UploadHost,
                              z = null == (i = m[0]) ? void 0 : i.UploadID,
                              S =
                                null == p || null == (n = p.SDKParam)
                                  ? void 0
                                  : n.server_encryption_mode,
                              w =
                                null == p || null == (o = p.SDKParam)
                                  ? void 0
                                  : o.server_gcm_encryption_mode,
                              k =
                                null == p ||
                                null == (s = p.InnerUploadAddress) ||
                                null == (s = s.AdvanceOption)
                                  ? void 0
                                  : s.EncryptionKey,
                              x = [],
                              E = [],
                              O =
                                (this.isImageBatchUpload && 1 < m.length
                                  ? m.forEach(function (e) {
                                      x.push(e.Auth), E.push(e.StoreUri);
                                    })
                                  : ((x = m[0].Auth), (E = m[0].StoreUri)),
                                "vod" === d &&
                                  (c = p.InnerUploadAddress.UploadNodes)
                                    .length &&
                                  1 < c.length &&
                                  (a = c.slice(1).map(function (e) {
                                    return {
                                      Cloud: e.Cloud,
                                      SessionKey: e.SessionKey,
                                      UploadHeader: e.UploadHeader,
                                      StoreInfo: e.StoreInfos[0],
                                      UploadHost: e.UploadHost,
                                    };
                                  })),
                                this.startOptions &&
                                  this.startOptions.enableSelectRoute &&
                                  ((f = !0),
                                  this.startOptions.selectRouteResult) &&
                                  (l =
                                    ((u =
                                      this.startOptions.selectRouteResult)[0] &&
                                      u[0].domainName) === v),
                                this.currFileCtx.sliceSize,
                                ie.checkIfGateway(b) ||
                                  this.currFileCtx.gatewayUpload);
                            this.isDirect ||
                              ((h = rF.minSliceSize(!1, O)) >
                                this.currFileCtx.sliceSize &&
                                (this.currFileCtx.sliceSize = Math.max(h))),
                              (t = ii(this.currFileCtx, {
                                key: this.options.key,
                                useBackupDomain:
                                  this.uploaderCtx.useBackupDomain,
                                signature: x,
                                type: "success",
                                extra: { message: "prepare upload success" },
                                stage: "preUpload",
                                oid: E,
                                systemTimeGap: this.systemTimeGap,
                                tosDomain: ""
                                  .concat(this.config.schema, "://")
                                  .concat(v),
                                xhr: e,
                                UploadHeader: rF.resolveHeader(
                                  b,
                                  this.currFileCtx.gatewayUpload
                                ),
                                SessionKey: y,
                                UploadID: z,
                                fallbackStoreInfoList: a,
                                stageStartTime: this._st,
                                stageEndTime: Date.now(),
                                duration: Date.now() - this._st,
                                totalDuration:
                                  Date.now() -
                                  this._st +
                                  this.currFileCtx.totalDuration,
                                useClientSelectRouteResult: l,
                                enableSelectRoute: f,
                                encryptionMode: S,
                                encryptionKey: k,
                                gcmEncryptionMode: w,
                              }));
                          } catch (t) {
                            return this.fail({
                              error: "catch error: ".concat(
                                t.message || t.toString()
                              ),
                              xhr: e,
                            });
                          }
                          return this.successProcess(t);
                        }
                        return this.fail({
                          error: "request fail: ".concat(
                            e.statusText || e.errText || "UNKNOWN"
                          ),
                          xhr: e,
                        });
                      },
                    },
                    {
                      key: "fail",
                      value: function (e) {
                        var t = this,
                          r = e.xhr,
                          i = e.errorCode || 1001e3,
                          n = "prepare upload error: UNKNOWN",
                          n =
                            (r &&
                              (n =
                                0 === r.status
                                  ? "prepare upload error: NETERROR"
                                  : e.message ||
                                    "prepare upload error: ".concat(r.status)),
                            ii(this.currFileCtx, {
                              extra: {
                                message: n,
                                error: e.error,
                                errorCode: i,
                              },
                              type: "error",
                              stage: "preUpload",
                              xhr: r,
                              stageStartTime: this._st,
                              stageEndTime: Date.now(),
                              duration: Date.now() - this._st,
                              totalDuration:
                                Date.now() -
                                this._st +
                                this.currFileCtx.totalDuration,
                            }));
                        this.isImageBatchUpload &&
                          ((n.successItems = []),
                          (n.failItems =
                            null == (e = this.currFileCtx)
                              ? void 0
                              : e.crc32Array.map(function (e, r) {
                                  return {
                                    crc32: e.crc32,
                                    fileSize:
                                      null == (e = t.currFileCtx)
                                        ? void 0
                                        : e.fileSize[r],
                                    fileName:
                                      null == (e = t.currFileCtx)
                                        ? void 0
                                        : e.fileName[r],
                                    finishSize: 0,
                                    success: !1,
                                  };
                                }))),
                          this.uploaderCtx._removeTaskCache(this.options.key),
                          this.failProcess(n);
                      },
                    },
                  ]),
                  (function (e, t) {
                    for (var r = 0; r < t.length; r++) {
                      var i = t[r];
                      (i.enumerable = i.enumerable || !1),
                        (i.configurable = !0),
                        "value" in i && (i.writable = !0),
                        Object.defineProperty(e, io(i.key), i);
                    }
                  })(t.prototype, e),
                  Object.defineProperty(t, "prototype", { writable: !1 }),
                  t
                );
              })();
              function il(e) {
                return (il =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              function ih() {
                return (ih = Object.assign
                  ? Object.assign.bind()
                  : function (e) {
                      for (var t = 1; t < arguments.length; t++) {
                        var r,
                          i = arguments[t];
                        for (r in i)
                          ({}).hasOwnProperty.call(i, r) && (e[r] = i[r]);
                      }
                      return e;
                    }).apply(null, arguments);
              }
              function id(e, t) {
                var r,
                  i = Object.keys(e);
                return (
                  Object.getOwnPropertySymbols &&
                    ((r = Object.getOwnPropertySymbols(e)),
                    t &&
                      (r = r.filter(function (t) {
                        return Object.getOwnPropertyDescriptor(e, t).enumerable;
                      })),
                    i.push.apply(i, r)),
                  i
                );
              }
              function ip(e) {
                return (
                  (e = (function (e, t) {
                    if ("object" != il(e) || !e) return e;
                    var r = e[Symbol.toPrimitive];
                    if (void 0 === r)
                      return ("string" === t ? String : Number)(e);
                    if (((r = r.call(e, t || "default")), "object" != il(r)))
                      return r;
                    throw TypeError(
                      "@@toPrimitive must return a primitive value."
                    );
                  })(e, "string")),
                  "symbol" == il(e) ? e : e + ""
                );
              }
              function ig() {
                try {
                  var e = !Boolean.prototype.valueOf.call(
                    Reflect.construct(Boolean, [], function () {})
                  );
                } catch (e) {}
                return (ig = function () {
                  return !!e;
                })();
              }
              function im(e) {
                return (im = Object.setPrototypeOf
                  ? Object.getPrototypeOf.bind()
                  : function (e) {
                      return e.__proto__ || Object.getPrototypeOf(e);
                    })(e);
              }
              function iy(e, t) {
                return (iy = Object.setPrototypeOf
                  ? Object.setPrototypeOf.bind()
                  : function (e, t) {
                      return (e.__proto__ = t), e;
                    })(e, t);
              }
              var i_ = (() => {
                var e;
                function t(e, r) {
                  var i, n, o;
                  return (
                    (function (e, t) {
                      if (!(e instanceof t))
                        throw TypeError("Cannot call a class as a function");
                    })(this, t),
                    (((n = im((n = t))),
                    (i = (function (e, t) {
                      if (t && ("object" == il(t) || "function" == typeof t))
                        return t;
                      if (void 0 !== t)
                        throw TypeError(
                          "Derived constructors may only return object or undefined"
                        );
                      return (function (e) {
                        if (void 0 === e)
                          throw ReferenceError(
                            "this hasn't been initialised - super() hasn't been called"
                          );
                        return e;
                      })(e);
                    })(
                      this,
                      ig()
                        ? Reflect.construct(n, [], im(this).constructor)
                        : n.apply(this, o)
                    ))).options = e),
                    (i.config = r),
                    (i.transport = new rq()),
                    (i.uploaderCtx = e.context),
                    (i.currFileCtx = e.context.tasks[e.key]),
                    i.eventInit(),
                    i
                  );
                }
                return (
                  (function (e, t) {
                    if ("function" != typeof t && null !== t)
                      throw TypeError(
                        "Super expression must either be null or a function"
                      );
                    (e.prototype = Object.create(t && t.prototype, {
                      constructor: { value: e, writable: !0, configurable: !0 },
                    })),
                      Object.defineProperty(e, "prototype", { writable: !1 }),
                      t && iy(e, t);
                  })(t, u.a),
                  (e = [
                    {
                      key: "initUpload",
                      value: function () {
                        var e = {
                            oid: this.currFileCtx.oid,
                            tosDomain: this.currFileCtx.tosDomain,
                          },
                          e = rF.urlTemplate(
                            "{tosDomain}/upload/v1/{oid}?uploadmode=part&phase=init",
                            e
                          ),
                          t = this.config.userId,
                          t = (function (e) {
                            for (var t = 1; t < arguments.length; t++) {
                              var r = null != arguments[t] ? arguments[t] : {};
                              t % 2
                                ? id(Object(r), !0).forEach(function (t) {
                                    var i, n;
                                    (i = t),
                                      (n = r[t]),
                                      (i = ip(i)) in e
                                        ? Object.defineProperty(e, i, {
                                            value: n,
                                            enumerable: !0,
                                            configurable: !0,
                                            writable: !0,
                                          })
                                        : (e[i] = n);
                                  })
                                : Object.getOwnPropertyDescriptors
                                ? Object.defineProperties(
                                    e,
                                    Object.getOwnPropertyDescriptors(r)
                                  )
                                : id(Object(r)).forEach(function (t) {
                                    Object.defineProperty(
                                      e,
                                      t,
                                      Object.getOwnPropertyDescriptor(r, t)
                                    );
                                  });
                            }
                            return e;
                          })(
                            {
                              Authorization: this.currFileCtx.signature,
                              "X-Storage-U": encodeURIComponent(t),
                            },
                            this.currFileCtx.UploadHeader
                          ),
                          r = this.currFileCtx.headers || this.config.headers,
                          r = rF.getHeaderFromHeaders(r, "Content-Type");
                        r && (t["Specified-Content-Type"] = r),
                          this.transport.send({
                            method: "post",
                            url: e,
                            headers: t,
                            timeout: this.config.gatewayTimeout,
                          });
                      },
                    },
                    {
                      key: "resolveUploadHeader",
                      value: function (e) {
                        return (
                          delete (e = e || {})["X-Storage-Mode"],
                          delete e["x-storage-mode"],
                          ih({}, e)
                        );
                      },
                    },
                    {
                      key: "start",
                      value: function (e, t, r) {
                        (this.successProcess = t),
                          (this.failProcess = r),
                          (this._st = Date.now()),
                          this.initUpload(e && e.changeNodeRetry);
                      },
                    },
                    {
                      key: "eventInit",
                      value: function () {
                        var e = this;
                        this.transport.on("complete", function (t) {
                          var r = null;
                          try {
                            var i,
                              n = JSON.parse(t.response),
                              o = null == (i = n.data) ? void 0 : i.uploadid;
                            if (2e3 !== n.code || !o)
                              return e.fail({
                                error: "fail! response.code: "
                                  .concat(n.code, ", fail message: ")
                                  .concat(n.message),
                                xhr: t,
                                errorCode: null == n ? void 0 : n.code,
                              });
                            r = ih(e.currFileCtx, {
                              UploadID: o,
                              percent: 0,
                              type: "success",
                              extra: { message: "init upload id success" },
                              stage: "initUploadID",
                              xhr: t,
                              stageStartTime: e._st,
                              stageEndTime: Date.now(),
                              duration: Date.now() - e._st,
                              totalDuration:
                                Date.now() -
                                e._st +
                                e.currFileCtx.totalDuration,
                            });
                          } catch (r) {
                            return e.fail({
                              error: "catch error: ".concat(
                                r.message || JSON.stringify(r)
                              ),
                              xhr: t,
                            });
                          }
                          return e.successProcess(r);
                        }),
                          this.transport.on("error", function (t) {
                            e.fail({
                              error: "request fail: ".concat(
                                t.statusText || t.errText || "UNKNOWN"
                              ),
                              xhr: t,
                            });
                          });
                      },
                    },
                    {
                      key: "fail",
                      value: function (e) {
                        var t = this.options.context,
                          r = this.options.key,
                          t = ih(t.tasks[r], {
                            extra: {
                              message: "init upload id error, ".concat(e.error),
                              errorCode: e.errorCode || 1002e3,
                            },
                            type: "error",
                            stage: "initUploadID",
                            xhr: e.xhr,
                            stageStartTime: this._st,
                            stageEndTime: Date.now(),
                            duration: Date.now() - this._st,
                            totalDuration:
                              Date.now() -
                              this._st +
                              this.currFileCtx.totalDuration,
                          });
                        this.uploaderCtx._removeTaskCache(this.options.key),
                          this.failProcess(t);
                      },
                    },
                  ]),
                  (function (e, t) {
                    for (var r = 0; r < t.length; r++) {
                      var i = t[r];
                      (i.enumerable = i.enumerable || !1),
                        (i.configurable = !0),
                        "value" in i && (i.writable = !0),
                        Object.defineProperty(e, ip(i.key), i);
                    }
                  })(t.prototype, e),
                  Object.defineProperty(t, "prototype", { writable: !1 }),
                  t
                );
              })();
              function ib(e) {
                return (ib =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              function iv(e, t) {
                var r,
                  i = Object.keys(e);
                return (
                  Object.getOwnPropertySymbols &&
                    ((r = Object.getOwnPropertySymbols(e)),
                    t &&
                      (r = r.filter(function (t) {
                        return Object.getOwnPropertyDescriptor(e, t).enumerable;
                      })),
                    i.push.apply(i, r)),
                  i
                );
              }
              function iz(e) {
                for (var t = 1; t < arguments.length; t++) {
                  var r = null != arguments[t] ? arguments[t] : {};
                  t % 2
                    ? iv(Object(r), !0).forEach(function (t) {
                        var i, n;
                        (i = t),
                          (n = r[t]),
                          (i = iS(i)) in e
                            ? Object.defineProperty(e, i, {
                                value: n,
                                enumerable: !0,
                                configurable: !0,
                                writable: !0,
                              })
                            : (e[i] = n);
                      })
                    : Object.getOwnPropertyDescriptors
                    ? Object.defineProperties(
                        e,
                        Object.getOwnPropertyDescriptors(r)
                      )
                    : iv(Object(r)).forEach(function (t) {
                        Object.defineProperty(
                          e,
                          t,
                          Object.getOwnPropertyDescriptor(r, t)
                        );
                      });
                }
                return e;
              }
              function iS(e) {
                return (
                  (e = (function (e, t) {
                    if ("object" != ib(e) || !e) return e;
                    var r = e[Symbol.toPrimitive];
                    if (void 0 === r)
                      return ("string" === t ? String : Number)(e);
                    if (((r = r.call(e, t || "default")), "object" != ib(r)))
                      return r;
                    throw TypeError(
                      "@@toPrimitive must return a primitive value."
                    );
                  })(e, "string")),
                  "symbol" == ib(e) ? e : e + ""
                );
              }
              function iw() {
                try {
                  var e = !Boolean.prototype.valueOf.call(
                    Reflect.construct(Boolean, [], function () {})
                  );
                } catch (e) {}
                return (iw = function () {
                  return !!e;
                })();
              }
              function ik(e) {
                return (ik = Object.setPrototypeOf
                  ? Object.getPrototypeOf.bind()
                  : function (e) {
                      return e.__proto__ || Object.getPrototypeOf(e);
                    })(e);
              }
              function ix(e, t) {
                return (ix = Object.setPrototypeOf
                  ? Object.setPrototypeOf.bind()
                  : function (e, t) {
                      return (e.__proto__ = t), e;
                    })(e, t);
              }
              var iE = (() => {
                  var e;
                  function t(e) {
                    var r,
                      i,
                      n,
                      o = e.sliceItem,
                      s = e.crc32,
                      a = e.url,
                      c = e.signature,
                      u = e.uploadHeader,
                      l = e.userId,
                      f = e.retryTime,
                      h = e.timeout,
                      e = e.method,
                      e = void 0 === e ? "POST" : e;
                    return (
                      (function (e, t) {
                        if (!(e instanceof t))
                          throw TypeError("Cannot call a class as a function");
                      })(this, t),
                      (((r = ik((r = t))),
                      (n = (function (e, t) {
                        if (t && ("object" == ib(t) || "function" == typeof t))
                          return t;
                        if (void 0 !== t)
                          throw TypeError(
                            "Derived constructors may only return object or undefined"
                          );
                        return (function (e) {
                          if (void 0 === e)
                            throw ReferenceError(
                              "this hasn't been initialised - super() hasn't been called"
                            );
                          return e;
                        })(e);
                      })(
                        this,
                        iw()
                          ? Reflect.construct(r, [], ik(this).constructor)
                          : r.apply(this, i)
                      ))).fileSlice = o),
                      (n.crc32 = s),
                      (n.uploadUrl = a),
                      (n.uploadHeader = u),
                      (n.signature = c),
                      (n.userId = l),
                      (n.retryTime = f || 0),
                      (n.method = e),
                      (n.retryCount = 0),
                      (n.timeout = h),
                      (n.ready = !1),
                      (n.cancel = !1),
                      (n.transport = new rq()),
                      n.eventInit(),
                      n
                    );
                  }
                  return (
                    (function (e, t) {
                      if ("function" != typeof t && null !== t)
                        throw TypeError(
                          "Super expression must either be null or a function"
                        );
                      (e.prototype = Object.create(t && t.prototype, {
                        constructor: {
                          value: e,
                          writable: !0,
                          configurable: !0,
                        },
                      })),
                        Object.defineProperty(e, "prototype", { writable: !1 }),
                        t && ix(e, t);
                    })(t, u.a),
                    (e = [
                      {
                        key: "upload",
                        value: function () {
                          this.isParamsValid() &&
                            ((this._st = Date.now()), this.transport) &&
                            this.transport.send({
                              method: this.method,
                              url: this.uploadUrl,
                              headers: iz(
                                {
                                  Authorization: this.signature,
                                  "Content-CRC32": this.crc32,
                                  "X-Storage-U": encodeURIComponent(
                                    this.userId
                                  ),
                                },
                                this.uploadHeader
                              ),
                              file: this.fileSlice,
                              binary: 1,
                              timeout: this.timeout,
                            });
                        },
                      },
                      {
                        key: "isParamsValid",
                        value: function () {
                          return this.fileSlice &&
                            (this.fileSlice.size || this.fileSlice.byteLength)
                            ? this.crc32
                              ? !!this.uploadUrl ||
                                (this.emit("error", {
                                  message: "slice upload failed: NOURL",
                                  crc32: this.crc32,
                                  size:
                                    this.fileSlice.size ||
                                    this.fileSlice.byteLength,
                                }),
                                !1)
                              : (this.emit("error", {
                                  message: "slice upload failed: NOCRC32",
                                  crc32: this.crc32,
                                  size:
                                    this.fileSlice.size ||
                                    this.fileSlice.byteLength,
                                }),
                                !1)
                            : (this.emit("error", {
                                message: "slice upload failed: NOCONTENT",
                                crc32: this.crc32,
                              }),
                              !1);
                        },
                      },
                      {
                        key: "eventInit",
                        value: function () {
                          var e = this;
                          this.transport.on("complete", function (t) {
                            try {
                              var r = JSON.parse(t.response);
                              2e3 === r.code ? e.success(t) : e.fail(t, r);
                            } catch (r) {
                              e.fail(t);
                            }
                          }),
                            this.transport.on("error", function (t) {
                              e.fail(t);
                            }),
                            this.transport.on("progress", function (t) {
                              e.process(t);
                            });
                        },
                      },
                      {
                        key: "success",
                        value: function (e) {
                          this.ready = !0;
                          var t = Date.now() - this._st,
                            r =
                              this.fileSlice.size || this.fileSlice.byteLength;
                          this.emit("complete", {
                            crc32: this.crc32,
                            size: r,
                            speed: r / t,
                            xhr: e,
                            sliceStartTime: this._st,
                            sliceEndTime: Date.now(),
                            sliceDuration: Date.now() - this._st,
                          });
                        },
                      },
                      {
                        key: "fail",
                        value: function (e) {
                          var t,
                            r,
                            i = this,
                            n =
                              1 < arguments.length && void 0 !== arguments[1]
                                ? arguments[1]
                                : null;
                          this.cancel ||
                            ((t = {
                              crc32: this.crc32,
                              size:
                                this.fileSlice.size ||
                                this.fileSlice.byteLength,
                              xhr: e,
                              sliceStartTime: this._st,
                              sliceEndTime: Date.now(),
                              sliceDuration: Date.now() - this._st,
                            }),
                            e && 401 === e.status
                              ? this.emit(
                                  "error",
                                  iz(
                                    {
                                      message:
                                        "slice upload failed: UNAUTHORIZED",
                                    },
                                    t
                                  )
                                )
                              : ((r = "slice upload failed: UNKNOWN"),
                                e &&
                                  (r = e.status
                                    ? "slice upload failed: ".concat(
                                        (null == n ? void 0 : n.message) ||
                                          e.status
                                      )
                                    : "slice upload failed: NETERROR"),
                                this.retryCount < this.retryTime
                                  ? (setTimeout(function () {
                                      i.emit(
                                        "retry",
                                        iz(
                                          iz({}, t),
                                          {},
                                          { retryCount: i.retryCount }
                                        )
                                      ),
                                        i.upload(!0, iz({ message: r }, t));
                                    }, 1e3),
                                    this.retryCount++)
                                  : this.emit(
                                      "error",
                                      iz(
                                        {
                                          message: r,
                                          errorCode:
                                            null == n ? void 0 : n.code,
                                        },
                                        t
                                      )
                                    )));
                        },
                      },
                      {
                        key: "process",
                        value: function (e) {
                          this.cancel ||
                            this.emit("progress", {
                              crc32: this.crc32,
                              loaded: e.loaded || 0,
                              total: e.total || 0,
                            });
                        },
                      },
                      {
                        key: "abort",
                        value: function () {
                          this.transport &&
                            ((this.cancel = !0), this.transport.abort());
                        },
                      },
                      {
                        key: "destroy",
                        value: function () {
                          this.transport = null;
                        },
                      },
                    ]),
                    (function (e, t) {
                      for (var r = 0; r < t.length; r++) {
                        var i = t[r];
                        (i.enumerable = i.enumerable || !1),
                          (i.configurable = !0),
                          "value" in i && (i.writable = !0),
                          Object.defineProperty(e, iS(i.key), i);
                      }
                    })(t.prototype, e),
                    Object.defineProperty(t, "prototype", { writable: !1 }),
                    t
                  );
                })(),
                t = r(2),
                iO = r.n(t);
              function iD(e) {
                return (iD =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              function iT() {
                return (iT = Object.assign
                  ? Object.assign.bind()
                  : function (e) {
                      for (var t = 1; t < arguments.length; t++) {
                        var r,
                          i = arguments[t];
                        for (r in i)
                          ({}).hasOwnProperty.call(i, r) && (e[r] = i[r]);
                      }
                      return e;
                    }).apply(null, arguments);
              }
              function iC(e, t) {
                (null == t || t > e.length) && (t = e.length);
                for (var r = 0, i = Array(t); r < t; r++) i[r] = e[r];
                return i;
              }
              function iA() {
                try {
                  var e = !Boolean.prototype.valueOf.call(
                    Reflect.construct(Boolean, [], function () {})
                  );
                } catch (e) {}
                return (iA = function () {
                  return !!e;
                })();
              }
              function iI(e) {
                return (iI = Object.setPrototypeOf
                  ? Object.getPrototypeOf.bind()
                  : function (e) {
                      return e.__proto__ || Object.getPrototypeOf(e);
                    })(e);
              }
              function ij(e, t) {
                return (ij = Object.setPrototypeOf
                  ? Object.setPrototypeOf.bind()
                  : function (e, t) {
                      return (e.__proto__ = t), e;
                    })(e, t);
              }
              var iB = (() => {
                var e;
                function t(e) {
                  var r,
                    i,
                    n,
                    o =
                      1 < arguments.length && void 0 !== arguments[1]
                        ? arguments[1]
                        : {};
                  return (
                    (function (e, t) {
                      if (!(e instanceof t))
                        throw TypeError("Cannot call a class as a function");
                    })(this, t),
                    (((r = iI((r = t))),
                    (n = (function (e, t) {
                      if (t && ("object" == iD(t) || "function" == typeof t))
                        return t;
                      if (void 0 !== t)
                        throw TypeError(
                          "Derived constructors may only return object or undefined"
                        );
                      return (function (e) {
                        if (void 0 === e)
                          throw ReferenceError(
                            "this hasn't been initialised - super() hasn't been called"
                          );
                        return e;
                      })(e);
                    })(
                      this,
                      iA()
                        ? Reflect.construct(r, [], iI(this).constructor)
                        : r.apply(this, i)
                    ))).file = e.file),
                    (n.context = e.context),
                    (n.key = e.key),
                    (n.config = o),
                    (n.finishArr = []),
                    (n.errorLength = 0),
                    (n.finishSize = 0),
                    (n.retryUploadTime = Number(o.retryUploadTime)),
                    (n.progressMonitorTime = Number(o.progressMonitorTime)),
                    (n.progressMonitorSpeed = Number(o.progressMonitorSpeed)),
                    (n.uploadSliceCount = Number(o.uploadSliceCount)),
                    (n.realtimeSpeedInterval = Number(o.realtimeSpeedInterval)),
                    (n.processRetry = 0),
                    (n.lastFinishSize = -1),
                    (n.lastProcessPercent = -1),
                    (n.lastIntervalSize = -1),
                    (n.lastCalculateSpeedTime = -1),
                    (n.lastCalculateSpeedSize = 0),
                    (n.uploadHandlers = {}),
                    n
                  );
                }
                return (
                  (function (e, t) {
                    if ("function" != typeof t && null !== t)
                      throw TypeError(
                        "Super expression must either be null or a function"
                      );
                    (e.prototype = Object.create(t && t.prototype, {
                      constructor: { value: e, writable: !0, configurable: !0 },
                    })),
                      Object.defineProperty(e, "prototype", { writable: !1 }),
                      t && ij(e, t);
                  })(t, u.a),
                  (e = [
                    {
                      key: "start",
                      value: function (e, t, r) {
                        (this.failProcess = r),
                          (this.successProcess = t),
                          (this.errorLength = 0),
                          (this.currentCtx = this.context.tasks[this.key]),
                          (this.crc32Array =
                            this.context.tasks[this.key].crc32Array),
                          (this.uploadSliceCount =
                            this.uploadSliceCount > this.crc32Array.length
                              ? this.crc32Array.length
                              : this.uploadSliceCount),
                          (this.lastIndex = 0),
                          (this.uploading = []),
                          this.currentCtx.useFallback &&
                            (this.crc32Array.forEach(function (e) {
                              (e.finished = !1), (e.loaded = 0), (e.speed = 0);
                            }),
                            (this.finishArr = []),
                            (this.finishSize = 0)),
                          (this._uploadSize = this.crc32Array.reduce(function (
                            e,
                            t
                          ) {
                            return e + (t.finished ? 0 : t.end - t.start);
                          },
                          0)),
                          (this._st = Date.now()),
                          (this._lastSaveTime = Date.now()),
                          (this.lastCalculateSpeedTime = this._st),
                          this.initWorker(),
                          this.setProgressMonitor(),
                          this.threadUpload();
                      },
                    },
                    {
                      key: "initWorker",
                      value: function () {
                        var e,
                          t = this;
                        this.worker ||
                          ((e = this.crc32Array),
                          (this.worker = new iO.a()),
                          (this.worker.onmessage = function (r) {
                            var i,
                              r =
                                (function (e) {
                                  if (Array.isArray(e)) return e;
                                })((i = r.data)) ||
                                (function (e, t) {
                                  var r =
                                    null == e
                                      ? null
                                      : ("undefined" != typeof Symbol &&
                                          e[Symbol.iterator]) ||
                                        e["@@iterator"];
                                  if (null != r) {
                                    var i,
                                      n,
                                      o,
                                      s,
                                      a = [],
                                      c = !0,
                                      u = !1;
                                    try {
                                      o = (r = r.call(e)).next;
                                      for (
                                        ;
                                        !(c = (i = o.call(r)).done) &&
                                        (a.push(i.value), a.length !== t);
                                        c = !0
                                      );
                                    } catch (e) {
                                      (u = !0), (n = e);
                                    } finally {
                                      try {
                                        if (
                                          !c &&
                                          null != r.return &&
                                          ((s = r.return()), Object(s) !== s)
                                        )
                                          return;
                                      } finally {
                                        if (u) throw n;
                                      }
                                    }
                                    return a;
                                  }
                                })(i, 4) ||
                                (function (e, t) {
                                  var r;
                                  if (e)
                                    return "string" == typeof e
                                      ? iC(e, 4)
                                      : "Map" ===
                                          (r =
                                            "Object" ===
                                              (r = {}.toString
                                                .call(e)
                                                .slice(8, -1)) && e.constructor
                                              ? e.constructor.name
                                              : r) || "Set" === r
                                      ? Array.from(e)
                                      : "Arguments" === r ||
                                        /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(
                                          r
                                        )
                                      ? iC(e, t)
                                      : void 0;
                                })(i, 4) ||
                                (function () {
                                  throw TypeError(
                                    "Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."
                                  );
                                })(),
                              n = r[0],
                              o = r[1],
                              s = r[2],
                              r = r[3],
                              a = new Date().getTime(),
                              c = e[s];
                            (c.crc32 = o),
                              (c.crc32StartTime = r),
                              (c.crc32EndTime = a),
                              (c.crc32Duration = a - r),
                              t.upload(c, n, s);
                          }));
                      },
                    },
                    {
                      key: "read",
                      value: function (e, t) {
                        var r = this,
                          i = this.file,
                          n = i.slice || i.webkitSlice || i.mozSlice,
                          o = new FileReader();
                        (o.onload = function (e) {
                          var i = new Date().getTime();
                          r.worker.postMessage(
                            [
                              e.target.result,
                              t,
                              i,
                              !!r.config.clientEncrypt,
                              r.currentCtx.clientEncryptKey,
                              r.crc32Array.length - 1 === t,
                            ],
                            [e.target.result]
                          );
                        }),
                          (o.onerror = function () {
                            r.stop(),
                              r.fail({
                                extra: {
                                  message: "An error occurred reading the file",
                                  errorCode: 1003003,
                                },
                              });
                          }),
                          o.readAsArrayBuffer(n.call(i, e.start, e.end));
                      },
                    },
                    {
                      key: "threadUpload",
                      value: function () {
                        if (this.uploading.length < this.uploadSliceCount) {
                          var e = this.lastIndex,
                            t = this.crc32Array[e];
                          if (t) {
                            if (t.finished) {
                              if (
                                -1 === this.finishArr.indexOf(t.start) &&
                                (this.finishArr.push(t.start),
                                this.finishArr.length >= this.crc32Array.length)
                              )
                                return this.stop(), void this.success();
                            } else
                              (t.loaded = 0),
                                this.uploading.push(e),
                                this.read(t, e);
                            this.lastIndex++, this.threadUpload();
                          }
                        }
                      },
                    },
                    {
                      key: "stop",
                      value: function () {
                        var e = this;
                        Object.keys(this.uploadHandlers).forEach(function (t) {
                          e.uploadHandlers[t].abort(),
                            e.uploadHandlers[t].destroy();
                        }),
                          (this.uploadHandlers = {}),
                          this.worker && this.worker.terminate(),
                          (this.worker = null),
                          this.clearMonitor();
                      },
                    },
                    {
                      key: "setProgressMonitor",
                      value: function () {
                        var e = this;
                        this.progressMonitorInterval = setInterval(function () {
                          var t,
                            r = e.finishSize;
                          r - e.lastIntervalSize <
                          (e.progressMonitorTime / 1e3) *
                            e.progressMonitorSpeed *
                            1024
                            ? ((t = iT(e.currentCtx, {
                                stage: "process",
                                type: "warn",
                                extra: {
                                  message: "percent are not updated in ".concat(
                                    e.progressMonitorTime,
                                    " seconds"
                                  ),
                                },
                              })),
                              e.context.logger.send(t),
                              e.context._broadcast("slowProgress", t),
                              e.clearMonitor())
                            : (e.lastIntervalSize = r);
                        }, this.progressMonitorTime);
                      },
                    },
                    {
                      key: "clearMonitor",
                      value: function () {
                        this.progressMonitorInterval &&
                          clearInterval(this.progressMonitorInterval);
                      },
                    },
                    {
                      key: "upload",
                      value: function (e, t, r) {
                        var i = this,
                          n = e.crc32,
                          o = {
                            part_number: r + 1,
                            uploadId: this.currentCtx.UploadID,
                            oid: this.currentCtx.oid,
                            tosDomain: this.currentCtx.tosDomain,
                          },
                          o = rF.urlTemplate(l, o),
                          s = this.config.userId,
                          a =
                            (this.config.clientEncrypt ||
                              this.config.useSliceBuffer ||
                              (t = rF.fileSlice(this.file, e.start, e.end)),
                            this.currentCtx.UploadHeader || {}),
                          c = this.currentCtx.headers || this.config.headers,
                          c = rF.getHeaderFromHeaders(c, "Content-Type"),
                          c =
                            (c && (a["Specified-Content-Type"] = c),
                            new iE({
                              sliceItem: t,
                              crc32: n,
                              url: o,
                              signature: this.currentCtx.signature,
                              uploadHeader: a,
                              userId: s,
                              method: "POST",
                              retryTime: this.retryUploadTime,
                              timeout: this.config.uploadTimeout,
                            }));
                        c.on("complete", function (t) {
                          1 === i.currentCtx.status &&
                            ((t.start = e.start),
                            (t.crc32StartTime = e.crc32StartTime),
                            (t.crc32EndTime = e.crc32EndTime),
                            (t.crc32Duration = e.crc32Duration),
                            (t.index = r),
                            i.fileSliceSuccess(t));
                        }),
                          c.on("error", function (t) {
                            1 === i.currentCtx.status &&
                              ((t.start = e.start),
                              (t.crc32StartTime = e.crc32StartTime),
                              (t.crc32EndTime = e.crc32EndTime),
                              (t.crc32Duration = e.crc32Duration),
                              (t.index = r),
                              i.fail(t));
                          }),
                          c.on("progress", function (t) {
                            1 === i.currentCtx.status &&
                              ((t.start = e.start),
                              (t.index = r),
                              i.process(t));
                          }),
                          c.on("retry", function (t) {
                            1 === i.currentCtx.status &&
                              ((t.start = e.start), (t.index = r), i.retry(t));
                          }),
                          c.upload(),
                          (this.uploadHandlers[r] = c);
                      },
                    },
                    {
                      key: "success",
                      value: function (e) {
                        this.finishArr = [];
                        var t = Date.now() - this._st,
                          t = this._uploadSize / t,
                          t = iT(this.currentCtx, {
                            type: "success",
                            stage: "process",
                            percent: 100,
                            extra: { message: "upload all success" },
                            speed: t,
                            xhr: e,
                            stageStartTime: this._st,
                            stageEndTime: Date.now(),
                            duration: Date.now() - this._st,
                            totalDuration:
                              Date.now() -
                              this._lastSaveTime +
                              this.currentCtx.totalDuration,
                            isAllFinish: !0,
                          });
                        this.worker && this.worker.terminate(),
                          this.successProcess(t);
                      },
                    },
                    {
                      key: "fail",
                      value: function (e) {
                        var t = this.errorFormat(e);
                        (t.type = "error"),
                          void 0 !== e.statusCode &&
                            iT(this.currentCtx, { statusCode: e.statusCode }),
                          this.errorLength ||
                            (this.context.logger.send(iT({}, t)),
                            this.stop(),
                            this.context._broadcast("error", t),
                            this.errorLength++),
                          this.failProcess(t);
                      },
                    },
                    {
                      key: "retry",
                      value: function (e) {
                        (e = this.errorFormat(e)),
                          this.context.logger.send(
                            iT({}, e, { type: "retry" })
                          );
                      },
                    },
                    {
                      key: "fileSliceSuccess",
                      value: function (e) {
                        var t,
                          r = e.index,
                          i = Date.now(),
                          n =
                            (-1 === this.finishArr.indexOf(e.start) &&
                              this.finishArr.push(e.start),
                            (this.crc32Array[r].finished = !0),
                            (this.crc32Array[r].speed = e.speed),
                            { message: "slice upload success" });
                        e.xhr &&
                          ((t = e.xhr),
                          (n.currentUrl = t.currentUrl || ""),
                          iT(this.currentCtx, {
                            req: { url: t.currentUrl, param: t.params },
                            res: {
                              status: t.status,
                              body: t.responseText,
                              header: t.getAllResponseHeaders(),
                            },
                          }),
                          delete e.xhr),
                          this.context.logger.send(
                            iT(this.currentCtx, {
                              stage: "process",
                              type: "success",
                              sliceIndex: r,
                              extra: n,
                              totalDuration:
                                i -
                                this._lastSaveTime +
                                this.currentCtx.totalDuration,
                              sliceStartTime: e.sliceStartTime,
                              sliceEndTime: e.sliceEndTime,
                              sliceDuration: e.sliceDuration,
                              crc32StartTime: e.crc32StartTime,
                              crc32EndTime: e.crc32EndTime,
                              crc32Duration: e.crc32Duration,
                            })
                          ),
                          (this._lastSaveTime = i),
                          this.uploading.splice(this.uploading.indexOf(r), 1),
                          this.uploadHandlers[r] &&
                            delete this.uploadHandlers[r],
                          this.finishArr.length >= this.crc32Array.length
                            ? (this.stop(), this.success(e.xhr))
                            : this.threadUpload();
                      },
                    },
                    {
                      key: "getFinishSize",
                      value: function (e, t) {
                        var r = t.crc32,
                          i = 0;
                        return (
                          e.forEach(function (e) {
                            e.crc32 === r
                              ? ((e.loaded = t.loaded), (i += t.loaded))
                              : (e.loaded || (e.loaded = 0), (i += e.loaded));
                          }),
                          i
                        );
                      },
                    },
                    {
                      key: "process",
                      value: function (e) {
                        var t = this.currentCtx.realtimeSpeed || 0,
                          r = this.currentCtx.fileSize,
                          i =
                            ((this.finishSize = this.getFinishSize(
                              this.crc32Array,
                              e
                            )),
                            this.finishSize > this.lastFinishSize &&
                              (((e = new Date()).getTime() -
                                this.lastCalculateSpeedTime >
                                this.realtimeSpeedInterval ||
                                !t) &&
                                ((n =
                                  e.getTime() - this.lastCalculateSpeedTime),
                                (t = Math.floor(
                                  (i =
                                    this.finishSize -
                                    this.lastCalculateSpeedSize) / n
                                )),
                                (this.lastCalculateSpeedTime = e.getTime()),
                                (this.lastCalculateSpeedSize =
                                  this.finishSize)),
                              (this.lastFinishSize = this.finishSize)),
                            Math.floor((this.finishSize / r) * 100) || 0),
                          n = iT(this.currentCtx, {
                            stage: "process",
                            percent: i,
                            realtimeSpeed: t,
                          });
                        i > this.lastProcessPercent &&
                          100 !== i &&
                          ((this.lastProcessPercent = i),
                          this.context._broadcast("progress", n));
                      },
                    },
                    {
                      key: "errorFormat",
                      value: function (e) {
                        var t = this.currentCtx.totalDuration,
                          r = Date.now() - this._st,
                          i = e.index,
                          n = e.crc32
                            ? {
                                message: e.message,
                                data: e.crc32,
                                size: e.size,
                              }
                            : e.extra,
                          o =
                            ((n.errorCode =
                              (null == (o = e.extra) ? void 0 : o.errorCode) ||
                              e.errorCode ||
                              1003e3),
                            iT(this.currentCtx, {
                              extra: n,
                              sliceIndex: i,
                              stage: "process",
                              req: {},
                              res: {},
                              totalDuration: r + t,
                              sliceStartTime: e.sliceStartTime,
                              sliceEndTime: e.sliceEndTime,
                              sliceDuration: e.sliceDuration,
                              crc32StartTime: e.crc32StartTime,
                              crc32EndTime: e.crc32EndTime,
                              crc32Duration: e.crc32Duration,
                            }));
                        return (
                          e.xhr &&
                            ((n = e.xhr),
                            (o.req = { url: e.xhr.currentUrl }),
                            (o.res = {
                              status: n.status,
                              body: n.responseText,
                              header: n.getAllResponseHeaders(),
                            }),
                            delete e.xhr),
                          o
                        );
                      },
                    },
                  ]),
                  (function (e, t) {
                    for (var r = 0; r < t.length; r++) {
                      var i,
                        n = t[r];
                      (n.enumerable = n.enumerable || !1),
                        (n.configurable = !0),
                        "value" in n && (n.writable = !0),
                        Object.defineProperty(
                          e,
                          ((i = (function (e, t) {
                            if ("object" != iD(e) || !e) return e;
                            var r = e[Symbol.toPrimitive];
                            if (void 0 === r)
                              return ("string" === t ? String : Number)(e);
                            if (
                              ((r = r.call(e, t || "default")),
                              "object" != iD(r))
                            )
                              return r;
                            throw TypeError(
                              "@@toPrimitive must return a primitive value."
                            );
                          })((i = n.key), "string")),
                          "symbol" == iD(i) ? i : i + ""),
                          n
                        );
                    }
                  })(t.prototype, e),
                  Object.defineProperty(t, "prototype", { writable: !1 }),
                  t
                );
              })();
              function iR(e) {
                return (iR =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              function iP() {
                return (iP = Object.assign
                  ? Object.assign.bind()
                  : function (e) {
                      for (var t = 1; t < arguments.length; t++) {
                        var r,
                          i = arguments[t];
                        for (r in i)
                          ({}).hasOwnProperty.call(i, r) && (e[r] = i[r]);
                      }
                      return e;
                    }).apply(null, arguments);
              }
              function iU(e, t) {
                var r,
                  i = Object.keys(e);
                return (
                  Object.getOwnPropertySymbols &&
                    ((r = Object.getOwnPropertySymbols(e)),
                    t &&
                      (r = r.filter(function (t) {
                        return Object.getOwnPropertyDescriptor(e, t).enumerable;
                      })),
                    i.push.apply(i, r)),
                  i
                );
              }
              function iM(e) {
                return (
                  (e = (function (e, t) {
                    if ("object" != iR(e) || !e) return e;
                    var r = e[Symbol.toPrimitive];
                    if (void 0 === r)
                      return ("string" === t ? String : Number)(e);
                    if (((r = r.call(e, t || "default")), "object" != iR(r)))
                      return r;
                    throw TypeError(
                      "@@toPrimitive must return a primitive value."
                    );
                  })(e, "string")),
                  "symbol" == iR(e) ? e : e + ""
                );
              }
              function iG() {
                try {
                  var e = !Boolean.prototype.valueOf.call(
                    Reflect.construct(Boolean, [], function () {})
                  );
                } catch (e) {}
                return (iG = function () {
                  return !!e;
                })();
              }
              function iF(e) {
                return (iF = Object.setPrototypeOf
                  ? Object.getPrototypeOf.bind()
                  : function (e) {
                      return e.__proto__ || Object.getPrototypeOf(e);
                    })(e);
              }
              function iN(e, t) {
                return (iN = Object.setPrototypeOf
                  ? Object.setPrototypeOf.bind()
                  : function (e, t) {
                      return (e.__proto__ = t), e;
                    })(e, t);
              }
              var iH = (() => {
                var e;
                function t(e, r) {
                  var i, n, o;
                  return (
                    (function (e, t) {
                      if (!(e instanceof t))
                        throw TypeError("Cannot call a class as a function");
                    })(this, t),
                    (((n = iF((n = t))),
                    (i = (function (e, t) {
                      if (t && ("object" == iR(t) || "function" == typeof t))
                        return t;
                      if (void 0 !== t)
                        throw TypeError(
                          "Derived constructors may only return object or undefined"
                        );
                      return (function (e) {
                        if (void 0 === e)
                          throw ReferenceError(
                            "this hasn't been initialised - super() hasn't been called"
                          );
                        return e;
                      })(e);
                    })(
                      this,
                      iG()
                        ? Reflect.construct(n, [], iF(this).constructor)
                        : n.apply(this, o)
                    ))).options = e),
                    (i.config = r),
                    (i.transport = new rq()),
                    i.eventInit(),
                    (i.errorCount = 0),
                    (i.uploaderCtx = e.context),
                    (i.currFileCtx = e.context.tasks[e.key]),
                    i
                  );
                }
                return (
                  (function (e, t) {
                    if ("function" != typeof t && null !== t)
                      throw TypeError(
                        "Super expression must either be null or a function"
                      );
                    (e.prototype = Object.create(t && t.prototype, {
                      constructor: { value: e, writable: !0, configurable: !0 },
                    })),
                      Object.defineProperty(e, "prototype", { writable: !1 }),
                      t && iN(e, t);
                  })(t, u.a),
                  (e = [
                    {
                      key: "mergeFile",
                      value: function () {
                        for (
                          var e = {
                              oid: this.currFileCtx.oid,
                              uploadId: this.currFileCtx.UploadID,
                              tosDomain: this.currFileCtx.tosDomain,
                            },
                            t = this.currFileCtx.crc32Array,
                            r = "",
                            i = 0;
                          i < t.length;
                          i++
                        )
                          r = (r ? "".concat(r, ",") : "")
                            .concat(i + 1, ":")
                            .concat(t[i].crc32);
                        var e = rF.urlTemplate(
                            "{tosDomain}/upload/v1/{oid}?uploadmode=part&phase=finish&uploadid={uploadId}",
                            e
                          ),
                          n = this.config.userId,
                          n = (function (e) {
                            for (var t = 1; t < arguments.length; t++) {
                              var r = null != arguments[t] ? arguments[t] : {};
                              t % 2
                                ? iU(Object(r), !0).forEach(function (t) {
                                    var i, n;
                                    (i = t),
                                      (n = r[t]),
                                      (i = iM(i)) in e
                                        ? Object.defineProperty(e, i, {
                                            value: n,
                                            enumerable: !0,
                                            configurable: !0,
                                            writable: !0,
                                          })
                                        : (e[i] = n);
                                  })
                                : Object.getOwnPropertyDescriptors
                                ? Object.defineProperties(
                                    e,
                                    Object.getOwnPropertyDescriptors(r)
                                  )
                                : iU(Object(r)).forEach(function (t) {
                                    Object.defineProperty(
                                      e,
                                      t,
                                      Object.getOwnPropertyDescriptor(r, t)
                                    );
                                  });
                            }
                            return e;
                          })(
                            {
                              Authorization: this.currFileCtx.signature,
                              "X-Storage-U": encodeURIComponent(n),
                            },
                            this.currFileCtx.UploadHeader
                          ),
                          o =
                            (this.config.clientEncrypt &&
                              ((n["x-upload-encryption-mode"] = 2),
                              (n["x-upload-encryption-key"] = btoa(
                                this.currFileCtx.clientEncryptKey
                              ))),
                            this.currFileCtx.headers || this.config.headers),
                          o = rF.getHeaderFromHeaders(o, "Content-Type");
                        o && (n["Specified-Content-Type"] = o),
                          ((null != (o = this.options) &&
                            o.useServerEncryption) ||
                            (null != (o = this.currFileCtx) &&
                              o.useGcmEncryptionMode)) &&
                            rF.pushEncrypyHeader(
                              n,
                              this.currFileCtx,
                              this.options.type
                            ),
                          this.transport.send({
                            method: "post",
                            url: e,
                            headers: n,
                            custom: r,
                          });
                      },
                    },
                    {
                      key: "start",
                      value: function (e, t, r) {
                        (this.successProcess = t),
                          (this.failProcess = r),
                          (this._st = Date.now()),
                          this.mergeFile();
                      },
                    },
                    {
                      key: "eventInit",
                      value: function () {
                        var e = this,
                          t = this.options.stage;
                        this.transport.on("complete", function (r) {
                          var i = null;
                          try {
                            var n,
                              o = JSON.parse(r.response);
                            if (
                              2e3 !== o.code ||
                              null == (n = o.data) ||
                              !n.key
                            )
                              return e.fail({
                                error: "fail! response.code: "
                                  .concat(o.code, ", fail message: ")
                                  .concat(o.message),
                                xhr: r,
                                errorCode: o.code,
                              });
                            i = iP(e.currFileCtx, {
                              stage: t,
                              type: "success",
                              hasMerge: !0,
                              extra: { message: "merge file success" },
                              xhr: r,
                              stageStartTime: e._st,
                              stageEndTime: Date.now(),
                              duration: Date.now() - e._st,
                              totalDuration:
                                Date.now() -
                                e._st +
                                e.currFileCtx.totalDuration,
                            });
                          } catch (t) {
                            return e.fail({
                              error: "response parse error: ".concat(
                                t.message || JSON.stringify(t)
                              ),
                              xhr: r,
                            });
                          }
                          return e.successProcess(i);
                        }),
                          this.transport.on("error", function (t) {
                            e.fail({
                              error: "request fail: ".concat(
                                t.statusText || t.errText
                              ),
                              xhr: t,
                            });
                          });
                      },
                    },
                    {
                      key: "getProcessIndex",
                      value: function (e) {
                        var t = 0;
                        return (
                          e.forEach(function (e, r) {
                            "process" === e.stage && (t = r);
                          }),
                          t
                        );
                      },
                    },
                    {
                      key: "fail",
                      value: function (e) {
                        (e = iP(this.currFileCtx, {
                          extra: {
                            message: "merge file error, ".concat(e.error),
                            errorCode: e.errorCode || 1004e3,
                          },
                          type: "error",
                          stage: this.options.stage,
                          xhr: e.xhr,
                          stageStartTime: this._st,
                          stageEndTime: Date.now(),
                          duration: Date.now() - this._st,
                          totalDuration:
                            Date.now() -
                            this._st +
                            this.currFileCtx.totalDuration,
                        })),
                          this.failProcess(e);
                      },
                    },
                  ]),
                  (function (e, t) {
                    for (var r = 0; r < t.length; r++) {
                      var i = t[r];
                      (i.enumerable = i.enumerable || !1),
                        (i.configurable = !0),
                        "value" in i && (i.writable = !0),
                        Object.defineProperty(e, iM(i.key), i);
                    }
                  })(t.prototype, e),
                  Object.defineProperty(t, "prototype", { writable: !1 }),
                  t
                );
              })();
              function iL(e) {
                return (iL =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              function iK() {
                return (iK = Object.assign
                  ? Object.assign.bind()
                  : function (e) {
                      for (var t = 1; t < arguments.length; t++) {
                        var r,
                          i = arguments[t];
                        for (r in i)
                          ({}).hasOwnProperty.call(i, r) && (e[r] = i[r]);
                      }
                      return e;
                    }).apply(null, arguments);
              }
              function iq() {
                try {
                  var e = !Boolean.prototype.valueOf.call(
                    Reflect.construct(Boolean, [], function () {})
                  );
                } catch (e) {}
                return (iq = function () {
                  return !!e;
                })();
              }
              function iW(e) {
                return (iW = Object.setPrototypeOf
                  ? Object.getPrototypeOf.bind()
                  : function (e) {
                      return e.__proto__ || Object.getPrototypeOf(e);
                    })(e);
              }
              function iV(e, t) {
                return (iV = Object.setPrototypeOf
                  ? Object.setPrototypeOf.bind()
                  : function (e, t) {
                      return (e.__proto__ = t), e;
                    })(e, t);
              }
              var iJ = (() => {
                var e;
                function t(e) {
                  var r,
                    i,
                    n,
                    o =
                      1 < arguments.length && void 0 !== arguments[1]
                        ? arguments[1]
                        : {};
                  return (
                    (function (e, t) {
                      if (!(e instanceof t))
                        throw TypeError("Cannot call a class as a function");
                    })(this, t),
                    (((r = iW((r = t))),
                    (n = (function (e, t) {
                      if (t && ("object" == iL(t) || "function" == typeof t))
                        return t;
                      if (void 0 !== t)
                        throw TypeError(
                          "Derived constructors may only return object or undefined"
                        );
                      return (function (e) {
                        if (void 0 === e)
                          throw ReferenceError(
                            "this hasn't been initialised - super() hasn't been called"
                          );
                        return e;
                      })(e);
                    })(
                      this,
                      iq()
                        ? Reflect.construct(r, [], iW(this).constructor)
                        : r.apply(this, i)
                    ))).options = e),
                    (n.file = e.file),
                    (n.context = e.context),
                    (n.key = e.key),
                    (n.isImageBatchUpload = e.isImageBatchUpload),
                    (n.config = o),
                    (n.finishArr = []),
                    (n.errorLength = 0),
                    (n.finishSize = 0),
                    (n.retryUploadTime = n.config.retryUploadTime || 0),
                    (n.processRetry = 0),
                    (n.lastFinishSize = -1),
                    (n.lastProcessPercent = -1),
                    (n.lastIntervalSize = -1),
                    (n.uploader = {}),
                    (n._uploadProcessMap = {}),
                    n
                  );
                }
                return (
                  (function (e, t) {
                    if ("function" != typeof t && null !== t)
                      throw TypeError(
                        "Super expression must either be null or a function"
                      );
                    (e.prototype = Object.create(t && t.prototype, {
                      constructor: { value: e, writable: !0, configurable: !0 },
                    })),
                      Object.defineProperty(e, "prototype", { writable: !1 }),
                      t && iV(e, t);
                  })(t, u.a),
                  (e = [
                    {
                      key: "start",
                      value: function (e, t, r) {
                        (this.failProcess = r),
                          (this.successProcess = t),
                          (this.currentCtx = this.context.tasks[this.key]),
                          (this.crc32Array =
                            this.context.tasks[this.key].crc32Array),
                          (this._uploadSize = this.isImageBatchUpload
                            ? this.currentCtx.fileSize.reduce(function (e, t) {
                                return e + t;
                              })
                            : this.file.size),
                          (this._st = Date.now()),
                          this.upload();
                      },
                    },
                    {
                      key: "stop",
                      value: function () {
                        var e = this;
                        this.uploader &&
                          Object.keys(this.uploader).forEach(function (t) {
                            e.uploader[t] &&
                              (e.uploader[t].abort(), e.uploader[t].destroy());
                          });
                      },
                    },
                    {
                      key: "upload",
                      value: function () {
                        for (
                          var e = this,
                            t = this.crc32Array.length,
                            r = 0,
                            i = 0,
                            n = 0;
                          n < t;
                          n++
                        ) {
                          var o = this.crc32Array[n],
                            s = o.buffer,
                            o = o.crc32,
                            a = this.currentCtx.signature,
                            a =
                              "[object Array]" ===
                              Object.prototype.toString.call(a)
                                ? a[n]
                                : a,
                            c = this.currentCtx.oid,
                            c =
                              "[object Array]" ===
                              Object.prototype.toString.call(c)
                                ? c[n]
                                : c,
                            u = {
                              oid: c,
                              tosDomain: this.currentCtx.tosDomain,
                            },
                            u = rF.urlTemplate(f, u),
                            l = this.config.userId,
                            h = void 0,
                            d = this.isImageBatchUpload
                              ? ((h = this.currentCtx.fileSize[n]),
                                this.currentCtx.fileName[n])
                              : ((h = this.file.size), this.file.name);
                          this._uploadProcessMap[o] &&
                          this._uploadProcessMap[o].success
                            ? (r += 1)
                            : ((this._uploadProcessMap[o] = {
                                crc32: o,
                                fileSize: h,
                                fileName: d,
                                oid: c,
                                finishSize: 0,
                                success: !1,
                              }),
                              (h = this.currentCtx.UploadHeader || {}),
                              (d =
                                this.currentCtx.headers || this.config.headers),
                              (c = rF.getHeaderFromHeaders(
                                d,
                                "Content-Type"
                              )) && (h["Specified-Content-Type"] = c),
                              ((null != (d = this.options) &&
                                d.useServerEncryption) ||
                                (null != (c = this.currentCtx) &&
                                  c.useGcmEncryptionMode)) &&
                                rF.pushEncrypyHeader(
                                  h,
                                  this.currentCtx,
                                  this.options.type
                                ),
                              (d = new iE({
                                sliceItem: s,
                                crc32: o,
                                url: u,
                                signature: a,
                                uploadHeader: h,
                                userId: l,
                                retryTime: this.retryUploadTime,
                                method: "POST",
                                timeout: this.config.uploadTimeout,
                              })).on("complete", function (n) {
                                r++,
                                  (e._uploadProcessMap[n.crc32].finishSize =
                                    n.size),
                                  (e._uploadProcessMap[n.crc32].success = !0),
                                  i + r === t && e.success(n.xhr);
                              }),
                              d.on("error", function (n) {
                                ++i + r === t &&
                                  (0 < r ? e.success(n.xhr) : e.fail(n));
                              }),
                              d.on("progress", function (t) {
                                e.process(t);
                              }),
                              (this.lastCalculateSpeedTime =
                                new Date().getTime()),
                              d.upload(),
                              (this.uploader[o] = d));
                        }
                      },
                    },
                    {
                      key: "success",
                      value: function (e) {
                        this.finishArr = [];
                        var t = Date.now() - this._st,
                          t = this._uploadSize / t,
                          r = iK(this.currentCtx, {
                            type: "success",
                            stage: "process",
                            percent: 99,
                            extra: { message: "direct upload success" },
                            speed: t,
                            xhr: e,
                            stageStartTime: this._st,
                            stageEndTime: Date.now(),
                            duration: Date.now() - this._st,
                            totalDuration:
                              Date.now() -
                              this._st +
                              this.currentCtx.totalDuration,
                          });
                        this.isImageBatchUpload &&
                          ((r.successItems = []),
                          (r.failItems = []),
                          Object.values(this._uploadProcessMap).forEach(
                            function (e) {
                              (e.success ? r.successItems : r.failItems).push(
                                e
                              );
                            }
                          )),
                          (this.uploader = null),
                          (this._uploadProcessMap = null),
                          this.successProcess(r);
                      },
                    },
                    {
                      key: "fail",
                      value: function (e) {
                        (e = iK(this.currentCtx, {
                          extra: {
                            message: "direct upload error: ".concat(
                              e.message || e.xhr.errText
                            ),
                            errorCode: e.errorCode || 1003e3,
                          },
                          type: "error",
                          stage: "process",
                          xhr: e.xhr,
                          stageStartTime: this._st,
                          stageEndTime: Date.now(),
                          duration: Date.now() - this._st,
                          totalDuration:
                            Date.now() -
                            this._st +
                            this.currentCtx.totalDuration,
                        })),
                          this.isImageBatchUpload &&
                            (e.failItems = Object.values(
                              this._uploadProcessMap
                            )),
                          (this.uploader = {}),
                          (this._uploadProcessMap = {}),
                          this.failProcess(e);
                      },
                    },
                    {
                      key: "process",
                      value: function (e) {
                        var t = this._uploadSize,
                          e =
                            ((this._uploadProcessMap[e.crc32].finishSize =
                              Math.max(
                                this._uploadProcessMap[e.crc32].finishSize,
                                e.loaded
                              )),
                            this.currentCtx.realtimeSpeed || 0),
                          r =
                            ((this.finishSize = Object.values(
                              this._uploadProcessMap
                            ).reduce(function (e, t) {
                              return e + t.finishSize;
                            }, 0)),
                            this.finishSize > this.lastFinishSize &&
                              ((e = Math.floor(
                                (r = this.finishSize - this.lastFinishSize) /
                                  (i =
                                    new Date().getTime() -
                                    this.lastCalculateSpeedTime)
                              )),
                              (this.lastFinishSize = this.finishSize),
                              (this.lastCalculateSpeedTime =
                                new Date().getTime())),
                            Math.floor((this.finishSize / t) * 100) || 0),
                          i = iK(this.currentCtx, {
                            stage: "process",
                            percent: r,
                            realtimeSpeed: e,
                          });
                        r > this.lastProcessPercent &&
                          100 !== r &&
                          ((this.lastProcessPercent = r),
                          this.context._broadcast("progress", i));
                      },
                    },
                  ]),
                  (function (e, t) {
                    for (var r = 0; r < t.length; r++) {
                      var i,
                        n = t[r];
                      (n.enumerable = n.enumerable || !1),
                        (n.configurable = !0),
                        "value" in n && (n.writable = !0),
                        Object.defineProperty(
                          e,
                          ((i = (function (e, t) {
                            if ("object" != iL(e) || !e) return e;
                            var r = e[Symbol.toPrimitive];
                            if (void 0 === r)
                              return ("string" === t ? String : Number)(e);
                            if (
                              ((r = r.call(e, t || "default")),
                              "object" != iL(r))
                            )
                              return r;
                            throw TypeError(
                              "@@toPrimitive must return a primitive value."
                            );
                          })((i = n.key), "string")),
                          "symbol" == iL(i) ? i : i + ""),
                          n
                        );
                    }
                  })(t.prototype, e),
                  Object.defineProperty(t, "prototype", { writable: !1 }),
                  t
                );
              })();
              function iZ(e) {
                return (iZ =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              function iX() {
                return (iX = Object.assign
                  ? Object.assign.bind()
                  : function (e) {
                      for (var t = 1; t < arguments.length; t++) {
                        var r,
                          i = arguments[t];
                        for (r in i)
                          ({}).hasOwnProperty.call(i, r) && (e[r] = i[r]);
                      }
                      return e;
                    }).apply(null, arguments);
              }
              function iQ() {
                try {
                  var e = !Boolean.prototype.valueOf.call(
                    Reflect.construct(Boolean, [], function () {})
                  );
                } catch (e) {}
                return (iQ = function () {
                  return !!e;
                })();
              }
              function i$(e) {
                return (i$ = Object.setPrototypeOf
                  ? Object.getPrototypeOf.bind()
                  : function (e) {
                      return e.__proto__ || Object.getPrototypeOf(e);
                    })(e);
              }
              function iY(e, t) {
                return (iY = Object.setPrototypeOf
                  ? Object.setPrototypeOf.bind()
                  : function (e, t) {
                      return (e.__proto__ = t), e;
                    })(e, t);
              }
              var i1 = (() => {
                var e;
                function t(e) {
                  var r,
                    i,
                    n,
                    o =
                      1 < arguments.length && void 0 !== arguments[1]
                        ? arguments[1]
                        : {};
                  return (
                    (function (e, t) {
                      if (!(e instanceof t))
                        throw TypeError("Cannot call a class as a function");
                    })(this, t),
                    (((r = i$((r = t))),
                    (n = (function (e, t) {
                      if (t && ("object" == iZ(t) || "function" == typeof t))
                        return t;
                      if (void 0 !== t)
                        throw TypeError(
                          "Derived constructors may only return object or undefined"
                        );
                      return (function (e) {
                        if (void 0 === e)
                          throw ReferenceError(
                            "this hasn't been initialised - super() hasn't been called"
                          );
                        return e;
                      })(e);
                    })(
                      this,
                      iQ()
                        ? Reflect.construct(r, [], i$(this).constructor)
                        : r.apply(this, i)
                    ))).options = e),
                    (n.file = e.file),
                    (n.context = e.context),
                    (n.key = e.key),
                    (n.config = o),
                    (n.errorLength = 0),
                    (n.retryUploadTime = Number(o.retryUploadTime)),
                    (n.maxUploadSliceCount = Number(o.uploadSliceCount)),
                    (n.uploadQueue = []),
                    (n.crc32Array = []),
                    (n.uploadSliceCount = 0),
                    (n.isCalcCrc32 = !1),
                    (n.isFileReading = !1),
                    (n.hasStarted = !1),
                    (n.hasCompleteUpload = !1),
                    (n.uploadingSliceList = []),
                    n
                  );
                }
                return (
                  (function (e, t) {
                    if ("function" != typeof t && null !== t)
                      throw TypeError(
                        "Super expression must either be null or a function"
                      );
                    (e.prototype = Object.create(t && t.prototype, {
                      constructor: { value: e, writable: !0, configurable: !0 },
                    })),
                      Object.defineProperty(e, "prototype", { writable: !1 }),
                      t && iY(e, t);
                  })(t, u.a),
                  (e = [
                    {
                      key: "start",
                      value: function (e, t, r) {
                        (this.failProcess = r),
                          (this.successProcess = t),
                          (this.currentCtx = this.context.tasks[this.key]),
                          (this.hasStarted = !0),
                          (this._st = Date.now()),
                          this.initWorker();
                      },
                    },
                    {
                      key: "initWorker",
                      value: function () {
                        var e = this;
                        this.worker ||
                          ((this.worker = new iO.a()),
                          (this.worker.onmessage = function (t) {
                            e.isCalcCrc32 = !1;
                            var r = t.data[0],
                              i = t.data[2],
                              n = t.data[1];
                            e.uploadQueue.forEach(function (t, o) {
                              t.index === i &&
                                ((e.uploadQueue[o].crc32 = n),
                                (e.uploadQueue[o].fileSliceBuffer = r),
                                (e.crc32Array[i] = { crc32: n }));
                            }),
                              e.startUploadQueue();
                          }),
                          this.startUploadQueue());
                      },
                    },
                    {
                      key: "addStreamSlice",
                      value: function (e) {
                        var t = this,
                          r = e.fileSlice,
                          i = e.index,
                          e = ((this.isFileReading = !0), new FileReader());
                        e.readAsArrayBuffer(r),
                          (e.onload = function (e) {
                            (t.isFileReading = !1),
                              (e = e.target.result),
                              t.uploadQueue.push({
                                fileSliceBuffer: e,
                                index: i,
                              }),
                              t.hasStarted && t.startUploadQueue();
                          });
                      },
                    },
                    {
                      key: "completeStreamUpload",
                      value: function () {
                        (this.hasCompleteUpload = !0),
                          0 !== this.uploadQueue.length ||
                            this.isFileReading ||
                            0 !== this.uploadingSliceList.length ||
                            this.success();
                      },
                    },
                    {
                      key: "startUploadQueue",
                      value: function () {
                        var e;
                        this.uploadSliceCount <= this.maxUploadSliceCount &&
                        0 < this.uploadQueue.length &&
                        this.uploadQueue[0].crc32
                          ? ((e = this.uploadQueue.shift()),
                            this.uploadSliceCount++,
                            this.upload({
                              sliceItem: e.fileSliceBuffer,
                              index: e.index,
                              crc32: e.crc32,
                            }))
                          : 0 < this.uploadQueue.length &&
                            !this.uploadQueue[0].crc32 &&
                            this.startCrc32Queue();
                      },
                    },
                    {
                      key: "startCrc32Queue",
                      value: function () {
                        if (!this.isCalcCrc32)
                          for (var e = 0; e < this.uploadQueue.length; e++) {
                            var t = this.uploadQueue[e];
                            if (!t.crc32) {
                              (this.isCalcCrc32 = !0),
                                this.worker.postMessage(
                                  [t.fileSliceBuffer, t.index],
                                  [t.fileSliceBuffer]
                                );
                              break;
                            }
                          }
                      },
                    },
                    {
                      key: "upload",
                      value: function (e) {
                        var t = this,
                          r = e.sliceItem,
                          i = e.crc32,
                          n = this.currentCtx.signature,
                          o = {
                            part_number: e.index + 1,
                            uploadId: this.currentCtx.UploadID,
                            oid: this.currentCtx.oid,
                            tosDomain: this.currentCtx.tosDomain,
                          },
                          e = rF.urlTemplate(l, o),
                          s = this.config.userId,
                          r = new iE({
                            sliceItem: r,
                            crc32: i,
                            url: e,
                            signature: n,
                            uploadHeader: this.currentCtx.UploadHeader,
                            userId: s,
                            retryTime: this.retryUploadTime,
                            method: "POST",
                            timeout: this.config.uploadTimeout,
                          });
                        r.on("complete", function (e) {
                          1 === t.currentCtx.status &&
                            ((e.index = o.part_number), t.fileSliceSuccess(e));
                        }),
                          r.on("error", function (e) {
                            1 === t.currentCtx.status &&
                              ((e.index = o.part_number), t.fail(e));
                          }),
                          0 > this.uploadingSliceList.indexOf(o.part_number) &&
                            this.uploadingSliceList.push(o.part_number),
                          r.upload();
                      },
                    },
                    {
                      key: "fileSliceSuccess",
                      value: function (e) {
                        var t = e.index,
                          r = Date.now(),
                          i = { message: "stream slice upload success" },
                          n =
                            (e.xhr &&
                              ((n = e.xhr),
                              (i.currentUrl = n.currentUrl || ""),
                              iX(this.currentCtx, {
                                req: { url: n.currentUrl, param: n.params },
                                res: {
                                  status: n.status,
                                  body: n.responseText,
                                  header: n.getAllResponseHeaders(),
                                },
                              }),
                              delete e.xhr),
                            this.context.logger.send(
                              iX(this.currentCtx, {
                                stage: "process",
                                type: "success",
                                sliceIndex: t,
                                extra: i,
                                totalDuration:
                                  r -
                                  this._lastSaveTime +
                                  this.currentCtx.totalDuration,
                              })
                            ),
                            iX(this.currentCtx, {
                              uploadQueueLength: this.uploadQueue.length,
                              sliceIndex: t,
                            })),
                          i =
                            (this.context._broadcast("stream-progress", n),
                            this.uploadSliceCount--,
                            this.uploadingSliceList.indexOf(t));
                        0 <= i && this.uploadingSliceList.splice(i, 1),
                          this.hasCompleteUpload &&
                          0 === this.uploadQueue.length &&
                          0 ===
                            (null == (r = this.uploadingSliceList)
                              ? void 0
                              : r.length)
                            ? this.success(e.xhr)
                            : this.startUploadQueue();
                      },
                    },
                    {
                      key: "success",
                      value: function (e) {
                        this.isAllSuccess ||
                          ((e = iX(this.currentCtx, {
                            type: "success",
                            stage: "process",
                            percent: 100,
                            extra: { message: "all slice upload success" },
                            crc32Array: this.crc32Array,
                            xhr: e,
                            stageStartTime: this._st,
                            stageEndTime: Date.now(),
                            duration: Date.now() - this._st,
                            totalDuration:
                              Date.now() -
                              this._st +
                              this.currentCtx.totalDuration,
                          })),
                          this.successProcess(e));
                      },
                    },
                    {
                      key: "fail",
                      value: function (e) {
                        var t = e.index,
                          e = iX(this.currentCtx, {
                            extra: { message: "stream slice upload error" },
                            type: "error",
                            stage: "process",
                            xhr: e.xhr,
                            stageStartTime: this._st,
                            stageEndTime: Date.now(),
                            duration: Date.now() - this._st,
                            totalDuration:
                              Date.now() -
                              this._st +
                              this.currentCtx.totalDuration,
                            sliceIndex: t,
                          });
                        this.context.logger.send(iX({}, e)),
                          this.context._broadcast("error", e);
                      },
                    },
                  ]),
                  (function (e, t) {
                    for (var r = 0; r < t.length; r++) {
                      var i,
                        n = t[r];
                      (n.enumerable = n.enumerable || !1),
                        (n.configurable = !0),
                        "value" in n && (n.writable = !0),
                        Object.defineProperty(
                          e,
                          ((i = (function (e, t) {
                            if ("object" != iZ(e) || !e) return e;
                            var r = e[Symbol.toPrimitive];
                            if (void 0 === r)
                              return ("string" === t ? String : Number)(e);
                            if (
                              ((r = r.call(e, t || "default")),
                              "object" != iZ(r))
                            )
                              return r;
                            throw TypeError(
                              "@@toPrimitive must return a primitive value."
                            );
                          })((i = n.key), "string")),
                          "symbol" == iZ(i) ? i : i + ""),
                          n
                        );
                    }
                  })(t.prototype, e),
                  Object.defineProperty(t, "prototype", { writable: !1 }),
                  t
                );
              })();
              function i0(e) {
                return (i0 =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              function i2(e, t) {
                var r,
                  i = Object.keys(e);
                return (
                  Object.getOwnPropertySymbols &&
                    ((r = Object.getOwnPropertySymbols(e)),
                    t &&
                      (r = r.filter(function (t) {
                        return Object.getOwnPropertyDescriptor(e, t).enumerable;
                      })),
                    i.push.apply(i, r)),
                  i
                );
              }
              function i4(e) {
                for (var t = 1; t < arguments.length; t++) {
                  var r = null != arguments[t] ? arguments[t] : {};
                  t % 2
                    ? i2(Object(r), !0).forEach(function (t) {
                        var i, n;
                        (i = t),
                          (n = r[t]),
                          (i = i8(i)) in e
                            ? Object.defineProperty(e, i, {
                                value: n,
                                enumerable: !0,
                                configurable: !0,
                                writable: !0,
                              })
                            : (e[i] = n);
                      })
                    : Object.getOwnPropertyDescriptors
                    ? Object.defineProperties(
                        e,
                        Object.getOwnPropertyDescriptors(r)
                      )
                    : i2(Object(r)).forEach(function (t) {
                        Object.defineProperty(
                          e,
                          t,
                          Object.getOwnPropertyDescriptor(r, t)
                        );
                      });
                }
                return e;
              }
              function i3() {
                return (i3 = Object.assign
                  ? Object.assign.bind()
                  : function (e) {
                      for (var t = 1; t < arguments.length; t++) {
                        var r,
                          i = arguments[t];
                        for (r in i)
                          ({}).hasOwnProperty.call(i, r) && (e[r] = i[r]);
                      }
                      return e;
                    }).apply(null, arguments);
              }
              function i5(e, t) {
                return (
                  (function (e) {
                    if (Array.isArray(e)) return e;
                  })(e) ||
                  (function (e, t) {
                    var r =
                      null == e
                        ? null
                        : ("undefined" != typeof Symbol &&
                            e[Symbol.iterator]) ||
                          e["@@iterator"];
                    if (null != r) {
                      var i,
                        n,
                        o,
                        s,
                        a = [],
                        c = !0,
                        u = !1;
                      try {
                        if (((o = (r = r.call(e)).next), 0 === t)) {
                          if (Object(r) !== r) return;
                          c = !1;
                        } else
                          for (
                            ;
                            !(c = (i = o.call(r)).done) &&
                            (a.push(i.value), a.length !== t);
                            c = !0
                          );
                      } catch (e) {
                        (u = !0), (n = e);
                      } finally {
                        try {
                          if (
                            !c &&
                            null != r.return &&
                            ((s = r.return()), Object(s) !== s)
                          )
                            return;
                        } finally {
                          if (u) throw n;
                        }
                      }
                      return a;
                    }
                  })(e, t) ||
                  (function (e, t) {
                    var r;
                    if (e)
                      return "string" == typeof e
                        ? i6(e, t)
                        : "Map" ===
                            (r =
                              "Object" ===
                                (r = {}.toString.call(e).slice(8, -1)) &&
                              e.constructor
                                ? e.constructor.name
                                : r) || "Set" === r
                        ? Array.from(e)
                        : "Arguments" === r ||
                          /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(r)
                        ? i6(e, t)
                        : void 0;
                  })(e, t) ||
                  (function () {
                    throw TypeError(
                      "Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."
                    );
                  })()
                );
              }
              function i6(e, t) {
                (null == t || t > e.length) && (t = e.length);
                for (var r = 0, i = Array(t); r < t; r++) i[r] = e[r];
                return i;
              }
              function i8(e) {
                return (
                  (e = (function (e, t) {
                    if ("object" != i0(e) || !e) return e;
                    var r = e[Symbol.toPrimitive];
                    if (void 0 === r)
                      return ("string" === t ? String : Number)(e);
                    if (((r = r.call(e, t || "default")), "object" != i0(r)))
                      return r;
                    throw TypeError(
                      "@@toPrimitive must return a primitive value."
                    );
                  })(e, "string")),
                  "symbol" == i0(e) ? e : e + ""
                );
              }
              function i9() {
                try {
                  var e = !Boolean.prototype.valueOf.call(
                    Reflect.construct(Boolean, [], function () {})
                  );
                } catch (e) {}
                return (i9 = function () {
                  return !!e;
                })();
              }
              function i7(e) {
                return (i7 = Object.setPrototypeOf
                  ? Object.getPrototypeOf.bind()
                  : function (e) {
                      return e.__proto__ || Object.getPrototypeOf(e);
                    })(e);
              }
              function ne(e, t) {
                return (ne = Object.setPrototypeOf
                  ? Object.setPrototypeOf.bind()
                  : function (e, t) {
                      return (e.__proto__ = t), e;
                    })(e, t);
              }
              var nt = (() => {
                var e;
                function t(e, r) {
                  var i, n, o;
                  return (
                    (function (e, t) {
                      if (!(e instanceof t))
                        throw TypeError("Cannot call a class as a function");
                    })(this, t),
                    (((n = i7((n = t))),
                    (i = (function (e, t) {
                      if (t && ("object" == i0(t) || "function" == typeof t))
                        return t;
                      if (void 0 !== t)
                        throw TypeError(
                          "Derived constructors may only return object or undefined"
                        );
                      return (function (e) {
                        if (void 0 === e)
                          throw ReferenceError(
                            "this hasn't been initialised - super() hasn't been called"
                          );
                        return e;
                      })(e);
                    })(
                      this,
                      i9()
                        ? Reflect.construct(n, [], i7(this).constructor)
                        : n.apply(this, o)
                    ))).options = e),
                    (i.config = r),
                    (i.uploaderCtx = e.context),
                    (i.currFileCtx = e.context.tasks[e.key]),
                    (i.isImageBatchUpload = !!i.options.isImageBatchUpload),
                    (i.skipCommit = e.skipCommit),
                    (i.transport = new rq()),
                    i.eventInit(),
                    i
                  );
                }
                return (
                  (function (e, t) {
                    if ("function" != typeof t && null !== t)
                      throw TypeError(
                        "Super expression must either be null or a function"
                      );
                    (e.prototype = Object.create(t && t.prototype, {
                      constructor: { value: e, writable: !0, configurable: !0 },
                    })),
                      Object.defineProperty(e, "prototype", { writable: !1 }),
                      t && ne(e, t);
                  })(t, u.a),
                  (e = [
                    {
                      key: "appendEncryptInfo",
                      value: function (e) {
                        var t, r, i, n;
                        ((null != (t = this.options) &&
                          t.useServerEncryption) ||
                          (null != (t = this.currFileCtx) &&
                            t.useGcmEncryptionMode)) &&
                          ((r = (t = this.currFileCtx).encryptionMode),
                          (i = t.gcmEncryptionMode),
                          (n = t.encryptionKey),
                          r || i) &&
                          ((e.EncryptionMode = (
                            t.useGcmEncryptionMode &&
                            i &&
                            this.options.type !== rx
                              ? i
                              : r
                          ).toString()),
                          (e.EncryptionKey = n));
                      },
                    },
                    {
                      key: "commitUpload",
                      value: function () {
                        var e,
                          t,
                          r = this.config.region,
                          i = "",
                          n = {},
                          o = this.uploaderCtx.useBackupDomain,
                          s = ie.checkServiceName(
                            this.options.type,
                            this.config,
                            this.options.serviceType
                          ),
                          o =
                            (s === rT &&
                              ((i = o
                                ? this.config.imageFallbackHost
                                : this.config.imageHost),
                              (n = (t = i5(this.createImageXParams(), 3))[0]),
                              (e = t[1]),
                              (t = t[2])),
                            "vod" === s &&
                              ((i = o
                                ? this.config.videoFallbackHost
                                : this.config.videoHost),
                              (n = (o = i5(this.createVodParams(), 3))[0]),
                              (e = o[1]),
                              (t = o[2])),
                            this.config.accountId &&
                              (n["X-Account-Id"] = this.config.accountId),
                            this.config.IsWriteMedia &&
                              (n.IsWriteMedia = !!this.config.IsWriteMedia),
                            (!0 !== this.options.IsWriteMedia &&
                              !1 !== this.options.IsWriteMedia) ||
                              (n.IsWriteMedia = this.options.IsWriteMedia),
                            this.config.openExperiment &&
                              ((n.app_id = this.config.appId),
                              (n.user_id = this.config.userId)),
                            rF.toQueryString(n)),
                          a =
                            this.currFileCtx.proxyStsToken ||
                            this.config.stsToken,
                          c = a.AccessKeyID,
                          u = a.AccessKeyId,
                          l = a.SecretAccessKey,
                          a = a.SessionToken,
                          f = rF.getDYAddHeader(
                            this.currFileCtx.headers || this.config.headers
                          ),
                          o = {
                            method: "POST",
                            url: "".concat(i, "?").concat(o),
                            timeout: this.config.gatewayTimeout,
                            region: r,
                            params: n,
                            headers: f,
                            pathname: rF.getPathByURL(i),
                          },
                          r =
                            ((o.custom = t),
                            (o.body = e),
                            s === rT &&
                              (o.headers["Content-Type"] = "application/json"),
                            new rW.a(o, s)),
                          n = this.currFileCtx.systemTimeGap,
                          f = n
                            ? new Date(new Date().getTime() + n)
                            : new Date();
                        r.addAuthorization(
                          {
                            accessKeyId: u || c,
                            secretAccessKey: l,
                            sessionToken: a,
                          },
                          f
                        ),
                          this.transport.send(o);
                      },
                    },
                    {
                      key: "createImageXParams",
                      value: function () {
                        var e = {
                            Action: "CommitImageUpload",
                            Version: "2018-08-01",
                          },
                          t = { SessionKey: this.currFileCtx.SessionKey },
                          r =
                            (this.options.type === rE &&
                              (this.currFileCtx.serviceId ||
                              (this.config.imageConfig &&
                                this.config.imageConfig.serviceId)
                                ? (e.ServiceId =
                                    this.currFileCtx.serviceId ||
                                    this.config.imageConfig.serviceId)
                                : (e.SpaceName =
                                    this.config.videoConfig &&
                                    this.config.videoConfig.spaceName),
                              Array.isArray(
                                (r =
                                  this.config.imageConfig &&
                                  this.config.imageConfig.processAction)
                              ) &&
                                0 < r.length &&
                                (t.Functions = r),
                              this.config.skipMeta) &&
                              (e.SkipMeta = !0),
                            this.options.type === rO &&
                              (e.ServiceId =
                                this.currFileCtx.serviceId ||
                                (this.config.objectConfig &&
                                  this.config.objectConfig.serviceId) ||
                                (this.config.imageConfig &&
                                  this.config.imageConfig.serviceId)),
                            this.appendEncryptInfo(t),
                            JSON.stringify(t));
                        return [e, t, r];
                      },
                    },
                    {
                      key: "createVodParams",
                      value: function () {
                        var e =
                            null == (e = this.config.videoConfig)
                              ? void 0
                              : e.spaceName,
                          t = {
                            Action: "CommitUploadInner",
                            Version: "2020-11-19",
                            SpaceName: (e =
                              this.options.type === rO &&
                              null != (t = this.config.objectConfig) &&
                              t.spaceName
                                ? null == (t = this.config.objectConfig)
                                  ? void 0
                                  : t.spaceName
                                : e),
                          },
                          e = {
                            SessionKey: this.currFileCtx.SessionKey,
                            Functions: [],
                          },
                          r =
                            this.config.videoConfig &&
                            this.config.videoConfig.processAction,
                          i =
                            (this.options.type === rO &&
                              null != (i = this.config.objectConfig) &&
                              i.processAction &&
                              (r =
                                null == (i = this.config.objectConfig)
                                  ? void 0
                                  : i.processAction),
                            Array.isArray(r) &&
                              0 < r.length &&
                              (e.Functions = r),
                            ((this.config.videoConfig &&
                              this.config.videoConfig.callbackArgs) ||
                              this.options.callbackArgs) &&
                              (e.CallbackArgs =
                                this.options.callbackArgs ||
                                this.config.videoConfig.callbackArgs),
                            this.options.type === rx &&
                              this.config.skipDownload &&
                              (t.SkipDownload = !0),
                            this.options.type === rO &&
                              this.options.objectSync &&
                              (e.ObjectSync = this.options.objectSync),
                            this.options.type === rx &&
                              this.options.needExactFormat &&
                              (e.needExactFormat =
                                this.options.needExactFormat),
                            this.appendEncryptInfo(e),
                            JSON.stringify(e));
                        return [t, e, i];
                      },
                    },
                    {
                      key: "start",
                      value: function (e, t, r) {
                        if (
                          ((this.successProcess = t),
                          (this.failProcess = r),
                          (this._st = Date.now()),
                          this.skipCommit)
                        )
                          return this.successProcess(
                            i3(this.currFileCtx, {
                              stage: "complete",
                              type: "success",
                              percent: 100,
                              extra: {
                                message: "upload successful, skip commit",
                              },
                              stageStartTime: this._st,
                              stageEndTime: Date.now(),
                              duration: Date.now() - this._st,
                              totalDuration:
                                Date.now() -
                                this._st +
                                this.currFileCtx.totalDuration,
                              skipCommit: this.skipCommit,
                            })
                          );
                        try {
                          this.commitUpload();
                        } catch (e) {
                          this.fail({
                            error: "catch error: ".concat(e.toString()),
                          });
                        }
                      },
                    },
                    {
                      key: "eventInit",
                      value: function () {
                        var e = this;
                        this.transport.on("complete", function (t) {
                          var r = null;
                          try {
                            var i = JSON.parse(t.response);
                            if (i.ResponseMetadata.Error)
                              return e.fail({
                                xhr: t,
                                errorCode: i.ResponseMetadata.Error.CodeN,
                                error: i.ResponseMetadata.Error.Code,
                                message: i.ResponseMetadata.Error.Message,
                              });
                            var n,
                              o,
                              s,
                              a = ie.checkServiceName(
                                e.options.type,
                                e.config,
                                e.options.serviceType
                              ),
                              c = i.Result,
                              u = {};
                            a === rT
                              ? e.isImageBatchUpload
                                ? ((n = c.Results),
                                  (o = c.PluginResult || []),
                                  (s = e.currFileCtx.successItems),
                                  n.forEach(function (e, t) {
                                    var r;
                                    (n[t] = i4(i4({}, n[t]), o[t])),
                                      2e3 ===
                                        (null == (r = n[t])
                                          ? void 0
                                          : r.UriStatus) &&
                                      s.find(function (e) {
                                        return (
                                          (null == e ? void 0 : e.oid) ===
                                          (null == (e = n[t]) ? void 0 : e.Uri)
                                        );
                                      })
                                        ? (n[t].UploadSuccess = !0)
                                        : (n[t].UploadSuccess = !1);
                                  }),
                                  (u = n))
                                : i3(
                                    (u = c.Results[0]),
                                    c.PluginResult && c.PluginResult[0]
                                  )
                              : (u = c.Results[0]),
                              (r = i3(e.currFileCtx, {
                                stage: "complete",
                                type: "success",
                                percent: 100,
                                extra: { message: "upload successful" },
                                uploadResult: u,
                                xhr: t,
                                stageStartTime: e._st,
                                stageEndTime: Date.now(),
                                duration: Date.now() - e._st,
                                totalDuration:
                                  Date.now() -
                                  e._st +
                                  e.currFileCtx.totalDuration,
                                skipCommit: e.skipCommit,
                              }));
                          } catch (r) {
                            return e.fail({
                              error: "catch error: ".concat(
                                r.message || r.toString()
                              ),
                              xhr: t,
                            });
                          }
                          return e.successProcess(r);
                        }),
                          this.transport.on("error", function (t) {
                            var r = {
                              error: "request fail: ".concat(
                                t.statusText || t.errText || "UNKNOWN"
                              ),
                              xhr: t,
                            };
                            if (t.response)
                              try {
                                var i = JSON.parse(t.response);
                                i.ResponseMetadata &&
                                  i.ResponseMetadata.Error &&
                                  ((r.errorCode =
                                    i.ResponseMetadata.Error.CodeN),
                                  (r.error = i.ResponseMetadata.Error.Code),
                                  (r.message =
                                    i.ResponseMetadata.Error.Message));
                              } catch (e) {
                                (r.error = t.response.toString()),
                                  (r.message = t.response.toString());
                              }
                            e.fail(r);
                          });
                      },
                    },
                    {
                      key: "fail",
                      value: function (e) {
                        var t = e.xhr,
                          r = e.errorCode || 1005e3,
                          i = "commit upload error: UNKNOWN",
                          i =
                            (t &&
                              (i =
                                0 === t.status
                                  ? "commit upload error: NETERROR"
                                  : e.message ||
                                    "commit upload error: ".concat(t.status)),
                            i3(this.currFileCtx, {
                              extra: {
                                message: i,
                                error: e.error,
                                errorCode: r,
                              },
                              type: "error",
                              stage: "complete",
                              xhr: t,
                              stageStartTime: this._st,
                              stageEndTime: Date.now(),
                              duration: Date.now() - this._st,
                              totalDuration:
                                Date.now() -
                                this._st +
                                this.currFileCtx.totalDuration,
                              skipCommit: this.skipCommit,
                            }));
                        this.failProcess(i);
                      },
                    },
                  ]),
                  (function (e, t) {
                    for (var r = 0; r < t.length; r++) {
                      var i = t[r];
                      (i.enumerable = i.enumerable || !1),
                        (i.configurable = !0),
                        "value" in i && (i.writable = !0),
                        Object.defineProperty(e, i8(i.key), i);
                    }
                  })(t.prototype, e),
                  Object.defineProperty(t, "prototype", { writable: !1 }),
                  t
                );
              })();
              function nr(e) {
                return (nr =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              function ni() {
                return (ni = Object.assign
                  ? Object.assign.bind()
                  : function (e) {
                      for (var t = 1; t < arguments.length; t++) {
                        var r,
                          i = arguments[t];
                        for (r in i)
                          ({}).hasOwnProperty.call(i, r) && (e[r] = i[r]);
                      }
                      return e;
                    }).apply(null, arguments);
              }
              function nn() {
                try {
                  var e = !Boolean.prototype.valueOf.call(
                    Reflect.construct(Boolean, [], function () {})
                  );
                } catch (e) {}
                return (nn = function () {
                  return !!e;
                })();
              }
              function no(e) {
                return (no = Object.setPrototypeOf
                  ? Object.getPrototypeOf.bind()
                  : function (e) {
                      return e.__proto__ || Object.getPrototypeOf(e);
                    })(e);
              }
              function ns(e, t) {
                return (ns = Object.setPrototypeOf
                  ? Object.setPrototypeOf.bind()
                  : function (e, t) {
                      return (e.__proto__ = t), e;
                    })(e, t);
              }
              var na = (() => {
                var e;
                function t(e, r, i, n) {
                  var o, s, a;
                  return (
                    (function (e, t) {
                      if (!(e instanceof t))
                        throw TypeError("Cannot call a class as a function");
                    })(this, t),
                    (((s = t),
                    (a = [e]),
                    (s = no(s)),
                    (o = (function (e, t) {
                      if (t && ("object" == nr(t) || "function" == typeof t))
                        return t;
                      if (void 0 !== t)
                        throw TypeError(
                          "Derived constructors may only return object or undefined"
                        );
                      return (function (e) {
                        if (void 0 === e)
                          throw ReferenceError(
                            "this hasn't been initialised - super() hasn't been called"
                          );
                        return e;
                      })(e);
                    })(
                      this,
                      nn()
                        ? Reflect.construct(s, a || [], no(this).constructor)
                        : s.apply(this, a)
                    ))).tasks = e),
                    (o.config = r),
                    (o.key = n),
                    (o.uploaderCtx = i),
                    (o.current = 0),
                    (o.length = o.tasks.length),
                    (o.taskError = {}),
                    (o.uploadList = []),
                    (o.retryTaskTime = r.retryTaskTime),
                    o
                  );
                }
                return (
                  (function (e, t) {
                    if ("function" != typeof t && null !== t)
                      throw TypeError(
                        "Super expression must either be null or a function"
                      );
                    (e.prototype = Object.create(t && t.prototype, {
                      constructor: { value: e, writable: !0, configurable: !0 },
                    })),
                      Object.defineProperty(e, "prototype", { writable: !1 }),
                      t && ns(e, t);
                  })(t, u.a),
                  (e = [
                    {
                      key: "start",
                      value: function (e) {
                        var t = this.tasks.shift();
                        if (t) {
                          this.current = t.index;
                          try {
                            this.execTask(t, e);
                          } catch (e) {
                            (e.key = t.key), this.fail(e);
                          }
                        }
                      },
                    },
                    {
                      key: "execTask",
                      value: function (e, t) {
                        var r,
                          i,
                          n = this,
                          o = e.key,
                          s = this.uploaderCtx,
                          a = s.tasks[o];
                        a &&
                          ((r = a.cacheTask),
                          (i = s.taskList[o].length),
                          !a.useFallback && r && 0 < e.index && e.index < r
                            ? this.start()
                            : ((a.currentTask = e.index),
                              1 === a.status &&
                                ((1 !== e.index &&
                                  "initUploadID" !== e.stage) ||
                                  (e.arg = ni(e.arg, t)),
                                e) &&
                                e.func.call(
                                  e.context,
                                  e.arg,
                                  function (r) {
                                    var c;
                                    s.taskList[o] &&
                                      ((c = s.taskList[o][e.index + 1]) &&
                                      0 !== e.index &&
                                      !a.isDirect &&
                                      n.config.enableDiskBreakpoint
                                        ? s._saveTask(o, {
                                            currentTask: c.index,
                                            stage: c.stage,
                                          })
                                        : e.index === i - 1 &&
                                          s._removeTaskCache(o),
                                      n.success(r),
                                      0 < n.tasks.length
                                        ? n.start(t)
                                        : s._queueSuccess(o));
                                  },
                                  function (r) {
                                    if (
                                      ((a.useFallback = !1),
                                      rC.TRANS.includes(rk[a.stage]) &&
                                        0 <
                                          (null == a ||
                                          null == (i = a.fallbackStoreInfoList)
                                            ? void 0
                                            : i.length) &&
                                        !a.stream)
                                    ) {
                                      var i = a.fallbackStoreInfoList.shift(),
                                        i =
                                          ((a.tosDomain = ""
                                            .concat(n.config.schema, "://")
                                            .concat(i.UploadHost)),
                                          (a.uploadHeader = i.UploadHeader),
                                          (a.oid = i.StoreInfo.StoreUri),
                                          (a.signature = i.StoreInfo.Auth),
                                          (a.SessionKey = i.SessionKey),
                                          (a.UploadID = i.StoreInfo.UploadID),
                                          (a.useFallback = !0),
                                          n.uploaderCtx.taskList[o].findIndex(
                                            function (e) {
                                              return (
                                                rk[e.stage] === rk.preUpload
                                              );
                                            }
                                          ));
                                      (n.tasks = n.uploaderCtx.taskList[
                                        o
                                      ].slice(i + 1)),
                                        n.uploaderCtx.logger.send(a, {
                                          type: "retryUseFallback",
                                          ex: "retry start from fallbackNodes.",
                                        }),
                                        n.start();
                                    } else if (r.xhr && r.xhr.status >= 400)
                                      n.fail(r);
                                    else if (3 === e.index && r.isDirect)
                                      n.fail(r);
                                    else if (
                                      !n.taskError[o] ||
                                      n.taskError[o] < n.retryTaskTime
                                    ) {
                                      n.taskError[o]
                                        ? n.taskError[o]++
                                        : (n.taskError[o] = 1),
                                        (i = n.errorFormat(r, !0)),
                                        n.uploaderCtx.logger.send(i);
                                      try {
                                        n.execTask(e, t);
                                      } catch (e) {
                                        (e.key = o), n.fail(e);
                                      }
                                    } else (r.key = o), n.fail(r);
                                  }
                                )));
                      },
                    },
                    {
                      key: "addTask",
                      value: function (e) {
                        this.tasks.push(e);
                      },
                    },
                    {
                      key: "success",
                      value: function (e) {
                        var t;
                        e.xhr &&
                          ((t = e.xhr),
                          (e.req = { url: t.currentUrl, param: t.params }),
                          (e.res = {
                            status: t.status,
                            header: t.getAllResponseHeaders(),
                            body: t.responseText,
                          }),
                          delete e.xhr),
                          ni(e, { type: "success" });
                        try {
                          this.uploaderCtx._broadcast(e.stage, e);
                        } catch (e) {}
                        this.uploaderCtx.logger.send(e);
                      },
                    },
                    {
                      key: "fail",
                      value: function (e) {
                        var t = this.uploaderCtx,
                          r = e.key,
                          e = this.errorFormat(e);
                        t._broadcast("error", e),
                          t.tasks[r].isBreak ? t._cancel(r) : t._pause(r),
                          t.logger.send(e);
                      },
                    },
                    {
                      key: "cancel",
                      value: function (e) {
                        var t,
                          r = this.key,
                          i = this.uploaderCtx.tasks[r].currentTask;
                        this.uploaderCtx.taskList[r].forEach(function (e) {
                          i === e.index && (t = e);
                        }),
                          e
                            ? 3 === i &&
                              this.uploaderCtx.tasks[r].isDirect &&
                              t &&
                              null != (e = t) &&
                              null != (e = e.context) &&
                              e.stop()
                            : ((this.tasks = []),
                              t && 3 === t.index && t.context.stop(),
                              this.uploaderCtx._removeTaskCache(r));
                      },
                    },
                    {
                      key: "restart",
                      value: function () {
                        this.uploadList.forEach(function (e) {
                          e.cancel = !1;
                        }),
                          this.start();
                      },
                    },
                    {
                      key: "errorFormat",
                      value: function (e, t) {
                        var r,
                          t = { type: t ? "retry" : "error" };
                        return (
                          e.xhr &&
                            ((r = e.xhr),
                            (e.req = { url: r.currentUrl, param: r.params }),
                            (e.res = {
                              status: r.status,
                              header: r.getAllResponseHeaders(),
                              body: r.responseText,
                            }),
                            e.extra &&
                              ((e.extra.req = e.req), (e.extra.res = e.res)),
                            delete e.xhr),
                          ni(e, t)
                        );
                      },
                    },
                  ]),
                  (function (e, t) {
                    for (var r = 0; r < t.length; r++) {
                      var i,
                        n = t[r];
                      (n.enumerable = n.enumerable || !1),
                        (n.configurable = !0),
                        "value" in n && (n.writable = !0),
                        Object.defineProperty(
                          e,
                          ((i = (function (e, t) {
                            if ("object" != nr(e) || !e) return e;
                            var r = e[Symbol.toPrimitive];
                            if (void 0 === r)
                              return ("string" === t ? String : Number)(e);
                            if (
                              ((r = r.call(e, t || "default")),
                              "object" != nr(r))
                            )
                              return r;
                            throw TypeError(
                              "@@toPrimitive must return a primitive value."
                            );
                          })((i = n.key), "string")),
                          "symbol" == nr(i) ? i : i + ""),
                          n
                        );
                    }
                  })(t.prototype, e),
                  Object.defineProperty(t, "prototype", { writable: !1 }),
                  t
                );
              })();
              function nc(e) {
                return (nc =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              function nu() {
                return (nu = Object.assign
                  ? Object.assign.bind()
                  : function (e) {
                      for (var t = 1; t < arguments.length; t++) {
                        var r,
                          i = arguments[t];
                        for (r in i)
                          ({}).hasOwnProperty.call(i, r) && (e[r] = i[r]);
                      }
                      return e;
                    }).apply(null, arguments);
              }
              function nl() {
                try {
                  var e = !Boolean.prototype.valueOf.call(
                    Reflect.construct(Boolean, [], function () {})
                  );
                } catch (e) {}
                return (nl = function () {
                  return !!e;
                })();
              }
              function nf(e) {
                return (nf = Object.setPrototypeOf
                  ? Object.getPrototypeOf.bind()
                  : function (e) {
                      return e.__proto__ || Object.getPrototypeOf(e);
                    })(e);
              }
              function nh(e, t) {
                return (nh = Object.setPrototypeOf
                  ? Object.setPrototypeOf.bind()
                  : function (e, t) {
                      return (e.__proto__ = t), e;
                    })(e, t);
              }
              var nd = (() => {
                var e;
                function t(e) {
                  var r, i, n;
                  return (
                    (function (e, t) {
                      if (!(e instanceof t))
                        throw TypeError("Cannot call a class as a function");
                    })(this, t),
                    (((i = t),
                    (n = [e]),
                    (i = nf(i)),
                    (r = (function (e, t) {
                      if (t && ("object" == nc(t) || "function" == typeof t))
                        return t;
                      if (void 0 !== t)
                        throw TypeError(
                          "Derived constructors may only return object or undefined"
                        );
                      return (function (e) {
                        if (void 0 === e)
                          throw ReferenceError(
                            "this hasn't been initialised - super() hasn't been called"
                          );
                        return e;
                      })(e);
                    })(
                      this,
                      nl()
                        ? Reflect.construct(i, n || [], nf(this).constructor)
                        : i.apply(this, n)
                    ))).config = nu({}, h)),
                    r._mergeOptions(r.config, e),
                    (r.tasks = {}),
                    (r.taskList = {}),
                    (r.cache = {}),
                    (r.storage = rF.storage(r, r.config.enableDiskBreakpoint)),
                    (r.logger = r.config.noLog
                      ? {
                          send: function () {
                            return !0;
                          },
                        }
                      : new rB(r.config, r)),
                    r
                  );
                }
                return (
                  (function (e, t) {
                    if ("function" != typeof t && null !== t)
                      throw TypeError(
                        "Super expression must either be null or a function"
                      );
                    (e.prototype = Object.create(t && t.prototype, {
                      constructor: { value: e, writable: !0, configurable: !0 },
                    })),
                      Object.defineProperty(e, "prototype", { writable: !1 }),
                      t && nh(e, t);
                  })(t, u.a),
                  (e = [
                    {
                      key: "_mergeOptions",
                      value: function (e, t) {
                        t &&
                          "object" === nc(t) &&
                          (nu(e, t),
                          Object.keys(t).forEach(function (r) {
                            "vodDomain" === r && (e.replace[r] = t[r]);
                          }));
                      },
                    },
                    {
                      key: "_setCache",
                      value: function (e, t) {
                        this.storage.setItem(e, t);
                      },
                    },
                    {
                      key: "_getCache",
                      value: function (e) {
                        return this.storage.getItem(e);
                      },
                    },
                    {
                      key: "_removeCache",
                      value: function (e) {
                        e ? this.storage.removeItem(e) : this.storage.clear();
                      },
                    },
                    {
                      key: "_addTask",
                      value: function (e, t) {
                        var r = this.tasks,
                          i = this.taskList;
                        r[e] && r[e].task
                          ? i[e].push(t)
                          : ((i[e] = []),
                            i[e].push(t),
                            (r[e] = r[e] || {}),
                            (r[e].task = new na([], this.config, this, e))),
                          r[e].task.addTask(t);
                      },
                    },
                    {
                      key: "_broadcast",
                      value: function (e, t, r) {
                        (r ||
                          1 === (r = this.tasks[t.key].status) ||
                          0 === r) &&
                          this.emit(e, t);
                      },
                    },
                    {
                      key: "_addCrc32ProcessTask",
                      value: function (e, t) {
                        var r =
                            2 < arguments.length && void 0 !== arguments[2]
                              ? arguments[2]
                              : {},
                          i = r.isDirect,
                          n = r.isImageBatchUpload,
                          e = new r7(
                            {
                              file: e.file,
                              context: this,
                              key: t,
                              isDirect: i,
                              isImageBatchUpload: void 0 !== n && n,
                              sliceSize: r.sliceSize,
                            },
                            this.config
                          ),
                          i = {
                            context: e,
                            func: e.start,
                            arg: {},
                            key: t,
                            index: 0,
                            stage: "crc32",
                          };
                        this._addTask(t, i);
                      },
                    },
                    {
                      key: "_addPreUploadTask",
                      value: function (e, t) {
                        var r =
                            2 < arguments.length && void 0 !== arguments[2]
                              ? arguments[2]
                              : {},
                          i = r.isDirect,
                          r = r.isImageBatchUpload,
                          i = {
                            file: e.file,
                            stsToken: e.stsToken,
                            context: this,
                            type: e.type || rx,
                            preUploadUriParams: e.preUploadUriParams || {},
                            storeKey: e.storeKey,
                            testHost: e.testHost,
                            key: t,
                            isDirect: i,
                            isImageBatchUpload: void 0 !== r && r,
                            fileSize: e.fileSize,
                            serviceType: e.serviceType || null,
                            fileExtension: e.fileExtension,
                          },
                          r = new iu(i, this.config),
                          e = {
                            context: r,
                            func: r.start,
                            arg: {},
                            key: t,
                            index: 1,
                            stage: "preUpload",
                          };
                        this._addTask(t, e);
                      },
                    },
                    {
                      key: "_addDirectUploadTask",
                      value: function (e, t) {
                        var r = (
                            2 < arguments.length && void 0 !== arguments[2]
                              ? arguments[2]
                              : {}
                          ).isImageBatchUpload,
                          r = new iJ(
                            {
                              type: e.type,
                              file: e.file,
                              context: this,
                              key: t,
                              isImageBatchUpload: void 0 !== r && r,
                              useServerEncryption: e.useServerEncryption,
                            },
                            this.config
                          ),
                          e = {
                            context: r,
                            func: r.start,
                            arg: {},
                            key: t,
                            index: 3,
                            stage: "process",
                          };
                        this._addTask(t, e);
                      },
                    },
                    {
                      key: "_addInitUploadIDTask",
                      value: function (e, t) {
                        (e = {
                          context: (e = new i_(
                            { file: e.file, context: this, key: t },
                            this.config
                          )),
                          func: e.start,
                          arg: {},
                          key: t,
                          index: 2,
                          stage: "initUploadID",
                        }),
                          this._addTask(t, e);
                      },
                    },
                    {
                      key: "_addUploadProcessTask",
                      value: function (e, t) {
                        (e = {
                          context: (e = new iB(
                            { file: e.file, context: this, key: t },
                            this.config
                          )),
                          func: e.start,
                          arg: {},
                          key: t,
                          index: 3,
                          stage: "process",
                        }),
                          this._addTask(t, e);
                      },
                    },
                    {
                      key: "_addStreamUploadTask",
                      value: function (e, t) {
                        this.streamUploadTask = new i1(
                          { context: this, key: t },
                          this.config
                        );
                        var r = {
                          context: this.streamUploadTask,
                          func: this.streamUploadTask.start,
                          arg: {},
                          key: t,
                          index: 3,
                          stage: "process",
                        };
                        this._addTask(t, r);
                      },
                    },
                    {
                      key: "_mergeFileTask",
                      value: function (e, t) {
                        (e = {
                          context: (e = new iH(
                            {
                              type: e.type,
                              file: e.file,
                              context: this,
                              stage: "fileMerge",
                              key: t,
                              useServerEncryption: e.useServerEncryption,
                            },
                            this.config
                          )),
                          func: e.start,
                          arg: {},
                          key: t,
                          index: 4,
                          stage: "fileMerge",
                        }),
                          this._addTask(t, e);
                      },
                    },
                    {
                      key: "_getMetaInfoTask",
                      value: function (e, t) {
                        var r =
                            2 < arguments.length && void 0 !== arguments[2]
                              ? arguments[2]
                              : {},
                          i = r.isImageBatchUpload,
                          r = r.skipCommit,
                          i = {
                            file: e.file,
                            context: this,
                            data: e.data,
                            type: e.type || rx,
                            callbackArgs: e.callbackArgs,
                            objectSync: e.objectSync,
                            needExactFormat: e.needExactFormat,
                            key: t,
                            isImageBatchUpload: void 0 !== i && i,
                            skipCommit: void 0 !== r && r,
                            serviceType: e.serviceType || null,
                            IsWriteMedia: e.IsWriteMedia,
                            useServerEncryption: e.useServerEncryption,
                          },
                          r = new nt(i, this.config),
                          e = {
                            context: r,
                            func: r.start,
                            arg: {},
                            key: t,
                            index: 5,
                            stage: "complete",
                          };
                        this._addTask(t, e);
                      },
                    },
                    {
                      key: "_addAllUploadProcess",
                      value: function (e, t) {
                        var r =
                            e.type === rE &&
                            "[object Array]" ===
                              Object.prototype.toString.call(e.file),
                          i =
                            ((this.tasks[t] = this.tasks[t] || {}),
                            (this.tasks[t].fileType = e.type || rx),
                            (this.tasks[t].fileSize = e.file && e.file.size),
                            (this.tasks[t].proxyStsToken = e.stsToken),
                            (this.tasks[t].headers = e.headers),
                            (this.tasks[t].serviceId = e.serviceId),
                            (this.tasks[t].useGcmEncryptionMode =
                              e.useGcmEncryptionMode),
                            (this.lastStsToken = e.stsToken),
                            (this.lastFile = e.file),
                            rF.getFileSliceLength(
                              e.file,
                              this.config.getSliceFunc
                            )),
                          n = e.file.size <= i || r,
                          i =
                            (e.useDirectUpload && (n = !0),
                            e.gatewayUpload &&
                              (this.tasks[t].fileSize < 5242880
                                ? (e.gatewayUpload = !1)
                                : ((this.tasks[t].gatewayUpload =
                                    !!e.gatewayUpload),
                                  (i = Math.max(5242880, i)))),
                            this._addCrc32ProcessTask(e, t, {
                              isDirect: n,
                              sliceSize: i,
                              isImageBatchUpload: r,
                            }),
                            this._addPreUploadTask(e, t, {
                              isDirect: n,
                              isImageBatchUpload: r,
                            }),
                            n
                              ? this._addDirectUploadTask(e, t, {
                                  isImageBatchUpload: r,
                                })
                              : (this._addInitUploadIDTask(e, t),
                                this._addUploadProcessTask(e, t),
                                this._mergeFileTask(e, t)),
                            !(
                              !this.config.skipCommit ||
                              ie.checkServiceName(e.type, this.config) !== rT
                            ));
                        this._getMetaInfoTask(e, t, {
                          isImageBatchUpload: r,
                          skipCommit: i,
                        });
                      },
                    },
                    {
                      key: "_addAllUploadProcessClientEncrypt",
                      value: function (e) {
                        var t,
                          r = this;
                        return e.type === rE && Array.isArray(e.file)
                          ? ((t = []),
                            e.file.forEach(function (i) {
                              t.push(
                                r._createClientEncryptTask({
                                  stsToken: e.stsToken,
                                  type: e.type,
                                  file: i,
                                })
                              );
                            }),
                            t)
                          : this._createClientEncryptTask(e);
                      },
                    },
                    {
                      key: "_createClientEncryptTask",
                      value: function (e) {
                        var t = rF.getUnique("file"),
                          r =
                            ((this.tasks[t] = this.tasks[t] || {}),
                            (this.tasks[t].fileType = e.type || rx),
                            (this.tasks[t].fileSize = e.file && e.file.size),
                            (this.tasks[t].proxyStsToken = e.stsToken),
                            (this.tasks[t].serviceId = e.serviceId),
                            (this.tasks[t].headers = e.headers),
                            (this.tasks[t].clientEncryptKey =
                              rF.generateKey(16)),
                            this._addCrc32ProcessTask(e, t, {
                              isDirect: !1,
                              isImageBatchUpload: !1,
                            }),
                            this._addPreUploadTask(e, t, {
                              isDirect: !1,
                              isImageBatchUpload: !1,
                            }),
                            this._addInitUploadIDTask(e, t),
                            this._addUploadProcessTask(e, t),
                            this._mergeFileTask(e, t),
                            !(
                              !this.config.skipCommit ||
                              ie.checkServiceName(e.type, this.config) !== rT
                            ));
                        return (
                          this._getMetaInfoTask(e, t, {
                            isImageBatchUpload: !1,
                            skipCommit: r,
                          }),
                          t
                        );
                      },
                    },
                    {
                      key: "_addAllStreamUploadProcess",
                      value: function (e, t) {
                        (this.tasks[t] = this.tasks[t] || {}),
                          (this.tasks[t].fileType = e.type || rx),
                          (this.tasks[t].proxyStsToken = e.stsToken),
                          (this.tasks[t].stream = !0),
                          this._addPreUploadTask(e, t),
                          this._addInitUploadIDTask(e, t),
                          this._addStreamUploadTask(e, t),
                          this._mergeFileTask(e, t),
                          this._getMetaInfoTask(e, t);
                      },
                    },
                    {
                      key: "_addStreamSlice",
                      value: function (e) {
                        var t = e.fileSlice;
                        this.streamUploadTask.addStreamSlice({
                          fileSlice: t,
                          index: e.index,
                        });
                      },
                    },
                    {
                      key: "_completeStreamUpload",
                      value: function () {
                        this.streamUploadTask.completeStreamUpload();
                      },
                    },
                    {
                      key: "_run",
                      value: function (e, t) {
                        var r = this.tasks,
                          i = navigator.userAgent
                            .toLowerCase()
                            .match(/msie ([\d.]+)/);
                        i && i[1] && 9 >= Number(i[1])
                          ? (this._broadcast(
                              "error",
                              nu(r[e], {
                                key: e,
                                status: 0,
                                stage: "browserError",
                                extra: {
                                  message:
                                    "cannot support the browser below ie10",
                                },
                                type: "error",
                              })
                            ),
                            this.logger.send(r[e]),
                            this._cancel(e))
                          : r[e] &&
                            (3 === r[e].status
                              ? this._restart(e)
                              : ((r[e].startTime = new Date().getTime()),
                                r[e].task &&
                                  1 !== r[e].status &&
                                  r[e].task.tasks.length &&
                                  ((r[e].status = 1),
                                  this.logger.send(
                                    nu({}, r[e], {
                                      extra: { message: "start upload" },
                                      type: "start",
                                      key: e,
                                    })
                                  ),
                                  r[e].task.start(t))));
                      },
                    },
                    {
                      key: "_selectRoute",
                      value: function (e, t) {
                        new r0(
                          {
                            stsToken: this.lastStsToken,
                            context: this,
                            type: rx,
                            file: this.lastFile,
                          },
                          this.config
                        ).start(e, t);
                      },
                    },
                    {
                      key: "_restart",
                      value: function (e) {
                        var t,
                          r,
                          i = this,
                          n = this.tasks;
                        n[e] &&
                          ((t = n[e].task),
                          (r = n[e].currentTask || 0),
                          this.taskList[e].forEach(function (n, o) {
                            n.index === r && (t.tasks = i.taskList[e].slice(o));
                          }),
                          t &&
                            1 !== n[e].status &&
                            t.tasks.length &&
                            ((n[e].status = 1), t.restart()));
                      },
                    },
                    {
                      key: "_cancel",
                      value: function (e) {
                        var t = this.tasks;
                        t[e] &&
                          ((t[e].status = 2),
                          t[e].task.cancel(),
                          delete this.taskList[e],
                          delete this.tasks[e]);
                      },
                    },
                    {
                      key: "_pause",
                      value: function (e) {
                        var t = this.tasks;
                        t[e] &&
                          ((t[e].status = 3),
                          t[e].task.cancel(!0),
                          t[e].isDirect || this._saveTask(e));
                      },
                    },
                    {
                      key: "_removeTaskCache",
                      value: function (e) {
                        var t = this.tasks;
                        t[e] && (t = t[e].crc32Key) && this._removeCache(t);
                      },
                    },
                    {
                      key: "_saveTask",
                      value: function (e, t) {
                        t = (e = nu({}, this.tasks[e], t || {})).crc32Key;
                        try {
                          t && this._setCache(t, this.serializeCacheInfo(e));
                        } catch (e) {}
                      },
                    },
                    {
                      key: "serializeCacheInfo",
                      value: function (e) {
                        var t = "";
                        delete e.task, delete e.xhr, delete e.crc32Array;
                        try {
                          t = JSON.stringify(e);
                        } catch (i) {
                          var r = {};
                          Object.keys(e).forEach(function (t) {
                            "task" !== t &&
                              "xhr" !== t &&
                              "crc32Array" !== t &&
                              (r[t] = e[t]);
                          }),
                            (t = JSON.stringify(r));
                        }
                        return t;
                      },
                    },
                    {
                      key: "_queueSuccess",
                      value: function (e) {
                        var t,
                          r = this.tasks;
                        r[e] &&
                          ((t = new Date()),
                          (r[e].endTime = t.getTime()),
                          (r[e].time = r[e].endTime - r[e].startTime),
                          (r[e].status = 0),
                          delete this.taskList[e],
                          delete r[e]);
                      },
                    },
                    {
                      key: "_removeFile",
                      value: function (e) {
                        delete this.tasks[e];
                      },
                    },
                    {
                      key: "_batchAction",
                      value: function (e, t) {
                        Object.keys(this.tasks).forEach(function (r) {
                          e && e(r, t);
                        });
                      },
                    },
                    {
                      key: "_refreshSTSToken",
                      value: function (e) {
                        var t = this,
                          r = this.tasks;
                        Object.keys(r).forEach(function (i) {
                          var i = r[i],
                            n = nu({}, i, { proxyStsToken: e }),
                            o = ((i.proxyStsToken = e), n.crc32Key);
                          o &&
                            ((i.proxyStsToken = e),
                            t._setCache(o, t.serializeCacheInfo(n)));
                        });
                      },
                    },
                    {
                      key: "_setOption",
                      value: function (e) {
                        this._mergeOptions(this.config, e);
                      },
                    },
                    {
                      key: "_getOption",
                      value: function (e) {
                        var t = nu({}, this.config);
                        return (
                          Object.keys(t).forEach(function (e) {
                            (-1 < e.indexOf("Url") ||
                              "replace" === e ||
                              "log" === e) &&
                              delete t[e];
                          }),
                          e ? t[e] : t
                        );
                      },
                    },
                    {
                      key: "_userCancel",
                      value: function (e) {
                        var t = this,
                          r = this.tasks;
                        e
                          ? (this._cancel(e),
                            this.logger.send(nu({}, r[e], { type: "cancel" })),
                            delete this.tasks[e])
                          : Object.keys(r).forEach(function (e) {
                              t._cancel(e),
                                t.logger.send(nu({}, r[e], { type: "cancel" })),
                                delete t.tasks[e];
                            });
                      },
                    },
                    {
                      key: "_userPause",
                      value: function (e) {
                        var t = this,
                          r = this.tasks;
                        e
                          ? (this._pause(e),
                            this.logger.send(nu({}, r[e], { type: "pause" })))
                          : Object.keys(r).forEach(function (e) {
                              t._pause(e),
                                t.logger.send(nu({}, r[e], { type: "pause" }));
                            });
                      },
                    },
                  ]),
                  (function (e, t) {
                    for (var r = 0; r < t.length; r++) {
                      var i,
                        n = t[r];
                      (n.enumerable = n.enumerable || !1),
                        (n.configurable = !0),
                        "value" in n && (n.writable = !0),
                        Object.defineProperty(
                          e,
                          ((i = (function (e, t) {
                            if ("object" != nc(e) || !e) return e;
                            var r = e[Symbol.toPrimitive];
                            if (void 0 === r)
                              return ("string" === t ? String : Number)(e);
                            if (
                              ((r = r.call(e, t || "default")),
                              "object" != nc(r))
                            )
                              return r;
                            throw TypeError(
                              "@@toPrimitive must return a primitive value."
                            );
                          })((i = n.key), "string")),
                          "symbol" == nc(i) ? i : i + ""),
                          n
                        );
                    }
                  })(t.prototype, e),
                  Object.defineProperty(t, "prototype", { writable: !1 }),
                  t
                );
              })();
              function np(e) {
                return (np =
                  "function" == typeof Symbol &&
                  "symbol" == typeof Symbol.iterator
                    ? function (e) {
                        return typeof e;
                      }
                    : function (e) {
                        return e &&
                          "function" == typeof Symbol &&
                          e.constructor === Symbol &&
                          e !== Symbol.prototype
                          ? "symbol"
                          : typeof e;
                      })(e);
              }
              function ng(e, t) {
                var r,
                  i = Object.keys(e);
                return (
                  Object.getOwnPropertySymbols &&
                    ((r = Object.getOwnPropertySymbols(e)),
                    t &&
                      (r = r.filter(function (t) {
                        return Object.getOwnPropertyDescriptor(e, t).enumerable;
                      })),
                    i.push.apply(i, r)),
                  i
                );
              }
              function nm(e) {
                for (var t = 1; t < arguments.length; t++) {
                  var r = null != arguments[t] ? arguments[t] : {};
                  t % 2
                    ? ng(Object(r), !0).forEach(function (t) {
                        var i, n;
                        (i = t),
                          (n = r[t]),
                          (i = ny(i)) in e
                            ? Object.defineProperty(e, i, {
                                value: n,
                                enumerable: !0,
                                configurable: !0,
                                writable: !0,
                              })
                            : (e[i] = n);
                      })
                    : Object.getOwnPropertyDescriptors
                    ? Object.defineProperties(
                        e,
                        Object.getOwnPropertyDescriptors(r)
                      )
                    : ng(Object(r)).forEach(function (t) {
                        Object.defineProperty(
                          e,
                          t,
                          Object.getOwnPropertyDescriptor(r, t)
                        );
                      });
                }
                return e;
              }
              function ny(e) {
                return (
                  (e = (function (e, t) {
                    if ("object" != np(e) || !e) return e;
                    var r = e[Symbol.toPrimitive];
                    if (void 0 === r)
                      return ("string" === t ? String : Number)(e);
                    if (((r = r.call(e, t || "default")), "object" != np(r)))
                      return r;
                    throw TypeError(
                      "@@toPrimitive must return a primitive value."
                    );
                  })(e, "string")),
                  "symbol" == np(e) ? e : e + ""
                );
              }
              function n_() {
                try {
                  var e = !Boolean.prototype.valueOf.call(
                    Reflect.construct(Boolean, [], function () {})
                  );
                } catch (e) {}
                return (n_ = function () {
                  return !!e;
                })();
              }
              function nb(e) {
                return (nb = Object.setPrototypeOf
                  ? Object.getPrototypeOf.bind()
                  : function (e) {
                      return e.__proto__ || Object.getPrototypeOf(e);
                    })(e);
              }
              function nv(e, t) {
                return (nv = Object.setPrototypeOf
                  ? Object.setPrototypeOf.bind()
                  : function (e, t) {
                      return (e.__proto__ = t), e;
                    })(e, t);
              }
              var nz = (() => {
                var e;
                function t() {
                  var e, r;
                  return (
                    (function (e, t) {
                      if (!(e instanceof t))
                        throw TypeError("Cannot call a class as a function");
                    })(this, t),
                    (e = t),
                    (r = arguments),
                    (e = nb(e)),
                    (function (e, t) {
                      if (t && ("object" == np(t) || "function" == typeof t))
                        return t;
                      if (void 0 !== t)
                        throw TypeError(
                          "Derived constructors may only return object or undefined"
                        );
                      return (function (e) {
                        if (void 0 === e)
                          throw ReferenceError(
                            "this hasn't been initialised - super() hasn't been called"
                          );
                        return e;
                      })(e);
                    })(
                      this,
                      n_()
                        ? Reflect.construct(e, r || [], nb(this).constructor)
                        : e.apply(this, r)
                    )
                  );
                }
                return (
                  (function (e, t) {
                    if ("function" != typeof t && null !== t)
                      throw TypeError(
                        "Super expression must either be null or a function"
                      );
                    (e.prototype = Object.create(t && t.prototype, {
                      constructor: { value: e, writable: !0, configurable: !0 },
                    })),
                      Object.defineProperty(e, "prototype", { writable: !1 }),
                      t && nv(e, t);
                  })(t, nd),
                  (e = [
                    {
                      key: "start",
                      value: function (e) {
                        var t = this,
                          r =
                            1 < arguments.length && void 0 !== arguments[1]
                              ? arguments[1]
                              : {};
                        (this.abort = !1),
                          r.selectRoute
                            ? this._selectRoute(r, function (r) {
                                (r = nm(
                                  nm({}, r),
                                  {},
                                  { enableSelectRoute: !0 }
                                )),
                                  e
                                    ? t._run(e, r)
                                    : t._batchAction(t._run.bind(t), r);
                              })
                            : e
                            ? this._run(e)
                            : this._batchAction(this._run.bind(this));
                      },
                    },
                    {
                      key: "addFile",
                      value: function (e) {
                        var t;
                        return e && ie.checkStsToken(e.stsToken)
                          ? e.file && this.config.clientEncrypt
                            ? this._addAllUploadProcessClientEncrypt(e)
                            : e.file
                            ? ((t = rF.getUnique("file")),
                              this._addAllUploadProcess(e, t),
                              t)
                            : null
                          : (this.emit("error", {
                              extra: { message: r5, errorCode: 1000002 },
                            }),
                            null);
                      },
                    },
                    {
                      key: "addImageFile",
                      value: function (e) {
                        var t;
                        return e && ie.checkStsToken(e.stsToken)
                          ? e.file
                            ? ((e.type = e.type || rE),
                              (t = rF.getUnique("file")),
                              this._addAllUploadProcess(e, t),
                              t)
                            : null
                          : (this.emit("error", {
                              extra: { message: r5, errorCode: 1000002 },
                            }),
                            null);
                      },
                    },
                    {
                      key: "addStreamUploadTask",
                      value: function (e) {
                        var t;
                        return e && ie.checkStsToken(e.stsToken)
                          ? ((t = rF.getUnique("file")),
                            this._addAllStreamUploadProcess(e, t),
                            t)
                          : (this.emit("error", {
                              extra: { message: r5, errorCode: 1000002 },
                            }),
                            null);
                      },
                    },
                    {
                      key: "addStreamSlice",
                      value: function (e) {
                        var t = e.fileSlice;
                        this._addStreamSlice({ fileSlice: t, index: e.index });
                      },
                    },
                    {
                      key: "completeStreamUpload",
                      value: function () {
                        this._completeStreamUpload();
                      },
                    },
                    {
                      key: "removeFile",
                      value: function (e) {
                        e && this._removeFile(e);
                      },
                    },
                    {
                      key: "cancel",
                      value: function (e) {
                        e
                          ? this._userCancel(e)
                          : this._batchAction(this._userCancel.bind(this));
                      },
                    },
                    {
                      key: "pause",
                      value: function (e) {
                        this._userPause(e);
                      },
                    },
                    {
                      key: "restart",
                      value: function (e) {
                        e
                          ? this._restart(e)
                          : this._batchAction(this._restart.bind(this));
                      },
                    },
                    {
                      key: "refreshSTSToken",
                      value: function (e) {
                        this._refreshSTSToken(e);
                      },
                    },
                    {
                      key: "setOption",
                      value: function (e) {
                        this._setOption(e);
                      },
                    },
                    {
                      key: "getOption",
                      value: function (e) {
                        return this._getOption(e);
                      },
                    },
                  ]),
                  (function (e, t) {
                    for (var r = 0; r < t.length; r++) {
                      var i = t[r];
                      (i.enumerable = i.enumerable || !1),
                        (i.configurable = !0),
                        "value" in i && (i.writable = !0),
                        Object.defineProperty(e, ny(i.key), i);
                    }
                  })(t.prototype, e),
                  Object.defineProperty(t, "prototype", { writable: !1 }),
                  t
                );
              })();
            },
          ]).default;
        }),
        (e.exports = r());
    },
  },
]);
