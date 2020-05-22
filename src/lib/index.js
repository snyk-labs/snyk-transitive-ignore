"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __asyncValues = (this && this.__asyncValues) || function (o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
};
exports.__esModule = true;
require("source-map-support/register");
var args = require('minimist')(process.argv.slice(2));
var fs_1 = require("fs");
var IGNORE_FILE = ".snyk_ignore";
function readStream(stream, encoding) {
    if (encoding === void 0) { encoding = "utf8"; }
    return new Promise(function (resolve, reject) {
        var data = "";
        stream.on("data", function (chunk) { return data += chunk; });
        stream.on("end", function () { return resolve(data); });
        stream.on("error", function (error) { return reject(error); });
    });
}
function checkIgnoreListMatch(ignoreItems, directDep) {
    // check for two types of matches
    // 1. when version is not specified in the ignore entry
    // 2. when version is specified in the ignore entry
    for (var _i = 0, ignoreItems_1 = ignoreItems; _i < ignoreItems_1.length; _i++) {
        var ignoreItem = ignoreItems_1[_i];
        // if ignoreItem contains an @ symbol, compare for equality to directDep
        if (ignoreItem.includes('@')) {
            if (ignoreItem == directDep) {
                console.log(ignoreItem + " matches " + directDep);
                return true;
            }
        }
        else {
            if (directDep.startsWith(ignoreItem.concat('@'))) {
                console.log(ignoreItem + " matches " + directDep);
                return true;
            }
        }
        // if ignoreItem does not contain an @symbol, compare for startsWith match
        // up to and including @ symbol (any version)
    }
}
function writeIgnoreEntry(vuln, path, expires, reason) {
    var writeString = "ignore:\n" +
        "  " + vuln + ":\n" +
        "    - '" + path + "':\n" +
        "        reason: " + reason + "\n" +
        "        expires: " + expires + "\n";
    fs_1.writeFileSync(IGNORE_FILE, writeString, { flag: 'a' });
}
var snykTransitiveIgnore = function () { return __awaiter(void 0, void 0, void 0, function () {
    var inputFile, fullPath, ignoreStrings;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                inputFile = "";
                fullPath = "";
                if (!(args.f && typeof args.f !== 'boolean')) return [3 /*break*/, 2];
                inputFile = args.f;
                return [4 /*yield*/, fs_1.readFileSync(inputFile).toString().split("\n")];
            case 1:
                ignoreStrings = _a.sent();
                return [3 /*break*/, 3];
            case 2:
                console.log('input file not specified');
                _a.label = 3;
            case 3: return [4 /*yield*/, readStream(process.stdin).then(function (data) {
                    var e_1, _a, e_2, _b;
                    return __awaiter(this, void 0, void 0, function () {
                        var issues, _c, _d, vuln, _e, _f, from, e_2_1, e_1_1;
                        return __generator(this, function (_g) {
                            switch (_g.label) {
                                case 0:
                                    issues = JSON.parse(String(data));
                                    _g.label = 1;
                                case 1:
                                    _g.trys.push([1, 19, 20, 25]);
                                    _c = __asyncValues(issues.vulnerabilities);
                                    _g.label = 2;
                                case 2: return [4 /*yield*/, _c.next()];
                                case 3:
                                    if (!(_d = _g.sent(), !_d.done)) return [3 /*break*/, 18];
                                    vuln = _d.value;
                                    fullPath = "";
                                    console.log("vuln id " + vuln.id);
                                    console.log("from direct dep " + vuln.from[1]);
                                    _g.label = 4;
                                case 4:
                                    _g.trys.push([4, 9, 10, 15]);
                                    _e = __asyncValues(vuln.from);
                                    _g.label = 5;
                                case 5: return [4 /*yield*/, _e.next()];
                                case 6:
                                    if (!(_f = _g.sent(), !_f.done)) return [3 /*break*/, 8];
                                    from = _f.value;
                                    if (fullPath != "") {
                                        fullPath += " > " + from;
                                    }
                                    else {
                                        fullPath = "" + from;
                                    }
                                    _g.label = 7;
                                case 7: return [3 /*break*/, 5];
                                case 8: return [3 /*break*/, 15];
                                case 9:
                                    e_2_1 = _g.sent();
                                    e_2 = { error: e_2_1 };
                                    return [3 /*break*/, 15];
                                case 10:
                                    _g.trys.push([10, , 13, 14]);
                                    if (!(_f && !_f.done && (_b = _e["return"]))) return [3 /*break*/, 12];
                                    return [4 /*yield*/, _b.call(_e)];
                                case 11:
                                    _g.sent();
                                    _g.label = 12;
                                case 12: return [3 /*break*/, 14];
                                case 13:
                                    if (e_2) throw e_2.error;
                                    return [7 /*endfinally*/];
                                case 14: return [7 /*endfinally*/];
                                case 15:
                                    console.log("full path " + fullPath);
                                    console.log("is " + vuln.from[1] + " in ignore list?");
                                    if (!checkIgnoreListMatch(ignoreStrings, vuln.from[1])) return [3 /*break*/, 17];
                                    return [4 /*yield*/, writeIgnoreEntry(vuln.id, vuln.from[1], "2100-01-01", "transitive ignore")];
                                case 16:
                                    _g.sent();
                                    _g.label = 17;
                                case 17: return [3 /*break*/, 2];
                                case 18: return [3 /*break*/, 25];
                                case 19:
                                    e_1_1 = _g.sent();
                                    e_1 = { error: e_1_1 };
                                    return [3 /*break*/, 25];
                                case 20:
                                    _g.trys.push([20, , 23, 24]);
                                    if (!(_d && !_d.done && (_a = _c["return"]))) return [3 /*break*/, 22];
                                    return [4 /*yield*/, _a.call(_c)];
                                case 21:
                                    _g.sent();
                                    _g.label = 22;
                                case 22: return [3 /*break*/, 24];
                                case 23:
                                    if (e_1) throw e_1.error;
                                    return [7 /*endfinally*/];
                                case 24: return [7 /*endfinally*/];
                                case 25: return [2 /*return*/];
                            }
                        });
                    });
                })];
            case 4:
                _a.sent();
                return [2 /*return*/];
        }
    });
}); };
snykTransitiveIgnore();
