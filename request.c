/*
 *  Copyright (C) 2004-2008 Christos Tsantilas
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA.
 */

#include "common.h"
#include "c-icap.h"
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>
#ifdef _NOTUSED
#include <sys/ioctl.h>
#endif

#include "debug.h"
#include "request.h"
#include "service.h"
#include "access.h"
#include "util.h"
#include "simple_api.h"
#include "cfg_param.h"
#include "stats.h"
#include "body.h"


extern int TIMEOUT;
extern int KEEPALIVE_TIMEOUT;
extern const char *DEFAULT_SERVICE;
extern int PIPELINING;
extern int CHECK_FOR_BUGGY_CLIENT;
extern int ALLOW204_AS_200OK_ZERO_ENCAPS;
extern int FAKE_ALLOW204;

/*This variable defined in mpm_server.c and become 1 when the child must
  halt imediatelly:*/
extern int CHILD_HALT;

#define FORBITTEN_STR "ICAP/1.0 403 Forbidden\r\n\r\n"
/*#define ISTAG         "\"5BDEEEA9-12E4-2\""*/

static int STAT_REQUESTS = -1;
static int STAT_FAILED_REQUESTS = -1;
static int STAT_BYTES_IN = -1;
static int STAT_BYTES_OUT = -1;
static int STAT_HTTP_BYTES_IN = -1;
static int STAT_HTTP_BYTES_OUT = -1;
static int STAT_BODY_BYTES_IN = -1;
static int STAT_BODY_BYTES_OUT = -1;
static int STAT_REQMODS = -1;
static int STAT_RESPMODS = -1;
static int STAT_OPTIONS = -1;
static int STAT_ALLOW204 = -1;

void request_stats_init()
{
    STAT_REQUESTS = ci_stat_entry_register("REQUESTS", STAT_INT64_T, "General");
    STAT_REQMODS = ci_stat_entry_register("REQMODS", STAT_INT64_T, "General");
    STAT_RESPMODS = ci_stat_entry_register("RESPMODS", STAT_INT64_T, "General");
    STAT_OPTIONS = ci_stat_entry_register("OPTIONS", STAT_INT64_T, "General");
    STAT_FAILED_REQUESTS = ci_stat_entry_register("FAILED REQUESTS", STAT_INT64_T, "General");
    STAT_ALLOW204 = ci_stat_entry_register("ALLOW 204", STAT_INT64_T, "General");
    STAT_BYTES_IN = ci_stat_entry_register("BYTES IN", STAT_KBS_T, "General");
    STAT_BYTES_OUT = ci_stat_entry_register("BYTES OUT", STAT_KBS_T, "General");
    STAT_HTTP_BYTES_IN = ci_stat_entry_register("HTTP BYTES IN", STAT_KBS_T, "General");
    STAT_HTTP_BYTES_OUT = ci_stat_entry_register("HTTP BYTES OUT", STAT_KBS_T, "General");
    STAT_BODY_BYTES_IN = ci_stat_entry_register("BODY BYTES IN", STAT_KBS_T, "General");
    STAT_BODY_BYTES_OUT = ci_stat_entry_register("BODY BYTES OUT", STAT_KBS_T, "General");
}

/*
 * ICAPリクエスト受信待ち
 *
 * 引数
 *   ci_connection_t  *conn         : コネクションオブジェクト
 *   int               secs         : 接続待ちタイムアウト時間(s)
 *   int               what_wait    : 待ち受け対象フラグ（ci_wait_for_read など）
 *
 * 復帰値
 *   >0 : select() 正常時の復帰値
 *   -1 : 異常（主に select() で異常）
 */
static int wait_for_data(ci_connection_t *conn, int secs, int what_wait)
{
    int wait_status;

    /*if we are going down do not wait....*/
    if (CHILD_HALT)
        return -1;

    do {
        wait_status = ci_connection_wait(conn, secs, what_wait);
        if (wait_status < 0)
            return -1;
        if (wait_status == 0 && CHILD_HALT) /*abort*/
            return -1;
    } while (wait_status & ci_wait_should_retry);

    if (wait_status == 0) /* timeout */
        return -1;

    return wait_status;
}

/*
 * リクエストオブジェクトの生成
 *
 * 引数
 *   ci_connection_t  *connection   : コネクションオブジェクト
 *
 * 復帰値
 *   NULL以外   : 正常
 *   NULL       : 異常
 */
ci_request_t *newrequest(ci_connection_t * connection)
{
    ci_request_t *req;
    int access;
    int len;
    ci_connection_t *conn;

    /* コネクションオブジェクト生成 */
    conn = (ci_connection_t *) malloc(sizeof(ci_connection_t));
    /* ★ NULL チェック */
    if (conn == NULL) {
        ci_debug_printf(1,
                        "Server Error: Error allocating memory \n");
        return NULL;
    }

    /*
     * ★ コネクションオブジェクト初期化
     * 現状は ci_copy_connection() で ci_connection_t の構造体メンバを
     * 全て複製しているため問題ない。
     * が、ci_connection_t のメンバを拡張したときに追加が漏れる事を考慮して
     * 初期化しておく
     */
    memset(conn, 0, sizeof(struct ci_connection_t));

    assert(conn);
    ci_copy_connection(conn, connection);
    /* req の malloc 失敗でNULLリターン */
    req = ci_request_alloc(conn);
    /* ★ NULL チェック */
    if (req == NULL) {
        free(conn);
        conn = NULL;

        ci_debug_printf(1,
                        "Server Error: Error allocating memory \n");
        return NULL;
    }

    /* acl 検査 */
    if ((access = access_check_client(req)) == CI_ACCESS_DENY) { /*Check for client access */
        len = strlen(FORBITTEN_STR);
        ci_connection_write(connection, FORBITTEN_STR, len, TIMEOUT);
        /* ci_request_destro() では conn, req が free される */
        ci_request_destroy(req);
        return NULL;          /*Or something that means authentication error */
    }


    req->access_type = access;
    return req;
}


/*
 * リクエストオブジェクトの再利用
 *
 * 引数
 *   ci_request_t     *req          : リクエストオブジェクト
 *   ci_connection_t  *connection   : コネクションオブジェクト
 *
 * 復帰値
 *   1  : 正常
 *   0  : 異常
 */
int recycle_request(ci_request_t * req, ci_connection_t * connection)
{
    int access;
    int len;

    /* req 初期化 */
    ci_request_reset(req);
    ci_copy_connection(req->connection, connection);

    /* acl 検査 */
    if ((access = access_check_client(req)) == CI_ACCESS_DENY) { /*Check for client access */
        len = strlen(FORBITTEN_STR);
        ci_connection_write(connection, FORBITTEN_STR, len, TIMEOUT);
        return 0;             /*Or something that means authentication error */
    }
    req->access_type = access;
    return 1;
}

/*
 * Keep-Alive 処理
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *   >0 : ICAPリクエスト待ち受け正常
 *        または、溢れデータあり(1)
 *   -1 : ICAPリクエスト待ち受け異常
 */
int keepalive_request(ci_request_t *req)
{
    /* Preserve extra read bytes*/
    char *pstrblock = req->pstrblock_read;
    int pstrblock_len = req->pstrblock_read_len;
    // Just reset without change or free memory
    ci_request_reset(req);
    if (PIPELINING) {
        /* パイプライン有効なら、溢れたリクエストデータを次リクエストデータとして使用する */
        req->pstrblock_read = pstrblock;
        req->pstrblock_read_len = pstrblock_len;
    }

    if (req->pstrblock_read && req->pstrblock_read_len > 0)
        return 1;

    /* ICAPリクエスト待ち合わせ */
    return wait_for_data(req->connection, KEEPALIVE_TIMEOUT, ci_wait_for_read);
}

/*Here we want to read in small blocks icap header becouse in most cases
 it will not bigger than 512-1024 bytes.
 So we are going to do small reads and small increments in icap headers size,
 to save some space and keep small the number of over-read bytes
*/
#define ICAP_HEADER_READSIZE 512

/*this function check if there is enough space in buffer buf ....*/
/*
 * リクエストヘッダ領域バッファのサイズ再割り当て
 *
 * 引数
 *   char  **buf        : バッファ領域
 *   int    *size       : 現在のバッファサイズ
 *   int     used       : 使用済みバッファサイズ
 *   int     mustadded  : 確保が必要なバッファサイズ
 *
 * 復帰値
 *   EC_100 : 正常
 *   EC_500 : 異常
 */
static int icap_header_check_realloc(char **buf, int *size, int used, int mustadded)
{
    char *newbuf;
    int len;
    if (*size - used < mustadded) {
        len = *size + ICAP_HEADER_READSIZE;
        newbuf = realloc(*buf, len);
        if (!newbuf) {
            return EC_500;
        }
        *buf = newbuf;
        *size = *size + ICAP_HEADER_READSIZE;
    }
    return EC_100;
}


/*
 * ICAPリクエストヘッダの受信処理
 *
 * 引数
 *   ci_request_t       *req        : リクエストオブジェクト
 *   ci_headers_list_t  *h          : バッファリスト
 *   int                 timeout    : 接続タイムアウト
 *
 * 復帰値
 *   EC_XXX
 */
static int ci_read_icap_header(ci_request_t * req, ci_headers_list_t * h, int timeout)
{
    int bytes, request_status = EC_100, i, eoh = 0, startsearch = 0, readed = 0;
    int wait_status = 0;
    char *buf_end;
    int dataPrefetch = 0;

    buf_end = h->buf;
    readed = 0;
    bytes = 0;

    /* パイプライン有効かつ溢れデータありなら、受信データの前に溢れデータをつける */
    if (PIPELINING && req->pstrblock_read && req->pstrblock_read_len > 0) {
        if ((request_status =
                    icap_header_check_realloc(&(h->buf), &(h->bufsize), req->pstrblock_read_len,
                                              ICAP_HEADER_READSIZE)) != EC_100)
            return request_status;
        memmove(h->buf, req->pstrblock_read, req->pstrblock_read_len);
        readed = req->pstrblock_read_len;
        buf_end = h->buf;
        bytes = readed;
        dataPrefetch = 1;
        req->pstrblock_read = NULL;
        req->pstrblock_read_len = 0;
        ci_debug_printf(5, "Get data from previous request read.\n");
    }

    do {

        /* 溢れデータがあれば、先に溢れデータを処理してからリクエストを待つ */

        if (!dataPrefetch) {
            if ((wait_status = wait_for_data(req->connection, timeout, ci_wait_for_read)) < 0)
                return EC_408;

            /*
             * read() でリクエスト受信
             * 非SSL通信なら bytes == 0 にはならない
             */
            bytes = ci_connection_read_nonblock(req->connection, buf_end, ICAP_HEADER_READSIZE);
            if (bytes < 0)
                return EC_408;

            if (bytes == 0) /*NOP? should retry?*/
                continue;

            readed += bytes;
            req->bytes_in += bytes;
        } else
            dataPrefetch = 0;

        /* ICAPヘッダの区切り位置を検査 */
        for (i = startsearch; i < bytes - 3; i++) {   /*search for end of header.... */
            if (strncmp(buf_end + i, "\r\n\r\n", 4) == 0) {
                /* buf_end をICAPヘッダの区切り手前まで進める */
                buf_end = buf_end + i + 2;
                eoh = 1;
                break;
            }
        }
        if (eoh)
            break;

        if ((request_status =
                    icap_header_check_realloc(&(h->buf), &(h->bufsize), readed,
                                              ICAP_HEADER_READSIZE)) != EC_100)
            break;
        buf_end = h->buf + readed;

        /* ICAPヘッダ区切り検査開始位置が受信ヘッダの先頭になるよう調整 */
        if (startsearch > -3)
            startsearch = (readed > 3 ? -3 : -readed);       /*Including the last 3 char ellements ....... */
    } while (1);

    h->bufused = buf_end - h->buf;     /* -1 ; */
    /* +2 は、ヘッダ区切り(\r\n)分 */
    req->pstrblock_read = buf_end + 2; /*after the \r\n\r\n. We keep the first \r\n and the other dropped.... */
    req->pstrblock_read_len = readed - h->bufused - 2; /*the 2 of the 4 characters \r\n\r\n and the '\0' character */
    req->request_bytes_in = h->bufused + 2; /*This is include the "\r\n\r\n" sequence*/
    return request_status;
}

/*
 * カプセル化ヘッダ（HTTPリクエストヘッダ or HTTPレスポンスヘッダ）受信処理
 *
 * 引数
 *   ci_request_t       *req    : リクエストオブジェクト
 *   ci_headers_list_t  *h      : バッファリスト
 *   int                 size   : Encapsulatedヘッダで通知されたカプセル化ヘッダサイズ
 *
 * 復帰値
 *   EC_100
 *   EC_500     : 処理異常
 *   CI_ERROR   : データ受信異常
 */
static int read_encaps_header(ci_request_t * req, ci_headers_list_t * h, int size)
{
    int bytes = 0, remains, readed = 0;
    char *buf_end = NULL;

    /* 受信データ格納バッファ割り当て */
    if (!ci_headers_setsize(h, size + (CHECK_FOR_BUGGY_CLIENT != 0 ? 2 : 0)))
        return EC_500;
    buf_end = h->buf;

    /* 溢れデータのセット */
    if (req->pstrblock_read_len > 0) {
        readed =
            (size > req->pstrblock_read_len ? req->pstrblock_read_len : size);
        memcpy(h->buf, req->pstrblock_read, readed);
        buf_end = h->buf + readed;
        if (size <= req->pstrblock_read_len) {        /*We have readed all this header....... */
            /* カプセル化ヘッダを全て受信済み */
            req->pstrblock_read = (req->pstrblock_read) + readed;
            req->pstrblock_read_len = (req->pstrblock_read_len) - readed;
        } else {
            req->pstrblock_read = NULL;
            req->pstrblock_read_len = 0;
        }
    }

    remains = size - readed;
    while (remains > 0) {
        /* クライアントからのデータ受信待ち */
        if (wait_for_data(req->connection, TIMEOUT, ci_wait_for_read) < 0)
            return CI_ERROR;
        /* 最大で残サイズ分の受信データを取得 */
        if ((bytes = ci_connection_read_nonblock(req->connection, buf_end, remains)) < 0)
            return CI_ERROR;
        remains -= bytes;
        buf_end += bytes;
        req->bytes_in += bytes;
    }

    /* カプセル化ヘッダ区切り位置を検査 */
    h->bufused = buf_end - h->buf;     // -1 ;
    if (strncmp(buf_end - 4, "\r\n\r\n", 4) == 0) {
        h->bufused -= 2;      /*eat the last 2 bytes of "\r\n\r\n" */
    } else if (CHECK_FOR_BUGGY_CLIENT && strncmp(buf_end - 2, "\r\n", 2) != 0) {
        // Some icap clients missing the "\r\n\r\n" after end of headers
        // when null-body is present.
        /* null-body の場合にカプセル化ヘッダ区切り文字を送らないICAPクライアントをサポート */
        ci_debug_printf(6, "Missing the CRLF after end of headers \n");
        *buf_end = '\r';
        *(buf_end + 1) = '\n';
        h->bufused += 2;
    }
    /*Currently we are counting only successfull http headers read.*/
    req->http_bytes_in += size;
    req->request_bytes_in += size;
    return EC_100;
}

/*
 * ICAPメソッド判定
 *
 * 引数
 *   char   *buf    : リクエストラインバッファ
 *   char  **end    : バッファのメソッド末尾位置
 *
 * 復帰値
 *   ICAP_OPTIONS   : OPTIONS
 *   ICAP_REQMOD    : REQMOD
 *   ICAP_RESPMOD   : RESPMOD
 *   -1             : 不明メソッド
 */
static int get_method(char *buf, char **end)
{
    if (!strncmp(buf, "OPTIONS", 7)) {
        *end = buf + 7;
        return ICAP_OPTIONS;
    } else if (!strncmp(buf, "REQMOD", 6)) {
        *end = buf + 6;
        return ICAP_REQMOD;
    } else if (!strncmp(buf, "RESPMOD", 7)) {
        *end = buf + 7;
        return ICAP_RESPMOD;
    } else {
        *end = buf;
        return -1;
    }
}

/*
 * ICAPリクエストライン解析処理
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *   char          *buf : リクエストラインバッファ
 *
 * 復帰値
 *   EC_XXX
 */
static int parse_request(ci_request_t * req, char *buf)
{
    char *start, *end;
    int servnamelen, len, args_len;
    int vmajor, vminor;
    ci_service_module_t *service = NULL;
    service_alias_t *salias = NULL;

    /* ICAPメソッド検査 */
    if ((req->type = get_method(buf, &end)) < 0)
        return EC_400;

    /*
     * ICAPメソッド後のスペース分 end を進める
     * ICAPメソッド後の複数スペースを許容している
     */
    while (*end == ' ') end++;
    start = end;

    /* URL検査 */
    if (strncasecmp(start, "icap://", 7) == 0)
        start = start + 7;
    else if (strncasecmp(start, "icaps://", 8) == 0)
        start = start + 8;
    else
        return EC_400;

    /* ホスト名の切り出し */
    len = strcspn(start, "/ ");
    end = start + len;
    servnamelen =
        (CI_MAXHOSTNAMELEN > len ? len : CI_MAXHOSTNAMELEN);
    memcpy(req->req_server, start, servnamelen);
    req->req_server[servnamelen] = '\0';
    if (*end == '/') { /*we are expecting service name*/
        /* サービス名検査 */
        start = ++end;
        while (*end && *end != ' ' && *end != '?')
            end++;
        len = end - start;

        len =
            (len < MAX_SERVICE_NAME ? len : MAX_SERVICE_NAME);
        if (len) {
            strncpy(req->service, start, len);
            req->service[len] = '\0';
        }

        if (*end == '?') {     /*args */
            /* クエリパラメタ検査 */
            start = ++end;
            if ((end = strchr(start, ' ')) != NULL) {
                args_len = strlen(req->args);
                len = end - start;
                if (args_len && len) {
                    req->args[args_len] = '&';
                    args_len++;
                }
                len = (len < (MAX_SERVICE_ARGS - args_len) ?
                       len : (MAX_SERVICE_ARGS - args_len));
                strncpy(req->args + args_len, start, len);
                req->args[args_len + len] = '\0';
            } else
                return EC_400;
        }      /*end of parsing args */
    }

    /*
     * URL後のスペース分 end を進める
     * URL後の複数スペースを許容している
     */
    while (*end == ' ')
        end++;
    start = end;

    /*
     * ICAPバージョン検査
     *
     * ICAPバージョン部は <数値>.<数値> の形式であれば正常扱いとなる
     * オリジナルでは <数値>.<数値> の後に任意文字列が存在しても正常となる
     * ex) ICAP/1.0aaaa
     */
    vminor = vmajor = -1;
    if (strncmp(start, "ICAP/", 5) == 0) {
        start += 5;
        /*
         * 変換対象の文字が数字でなければ strtol は 0 を返す
         * end には変換不可能な文字の最初の位置が格納される
         */
        vmajor = strtol(start, &end, 10);
        if (vmajor > 0 && *end == '.') {
            start = end + 1;
            vminor = strtol(start, &end, 10);
            if (end == start) /*no chars parsed*/
                vminor = -1;
            /* ★ マイナーバージョン後に文字列がないことを検査 */
            if (*end) {
                vminor = -1;
            }

        }
    }

    if (vminor == -1 || vmajor < 1)
        return EC_400;

    /*
     * URLからサービス名取得できなければ既定サービス名を設定
     * 既定サービス名は DefaultService で設定する（未設定時はNULL）
     */
    if (req->service[0] == '\0' && DEFAULT_SERVICE) { /*No service name defined*/
        strncpy(req->service, DEFAULT_SERVICE, MAX_SERVICE_NAME);
        /* ★ バッファオーバーフロー対策 */
        req->service[MAX_SERVICE_NAME] = '\0';
    }

    /* 有効なサービス名か検査 */
    if (req->service[0] != '\0') {
        if (!(service = find_service(req->service))) { /*else search for an alias */
            if ((salias = find_service_alias(req->service))) {
                service = salias->service;
                if (salias->args[0] != '\0')
                    strcpy(req->args, salias->args);
            }
        }
    }
    req->current_service_mod = service;

    if (!req->current_service_mod)
        return EC_404; /*Service not found*/

    /* リクエストメソッドが指定サービスで有効なメソッドか検査 */
    if (!ci_method_support
            (req->current_service_mod->mod_type, req->type)
            && req->type != ICAP_OPTIONS) {
        return EC_405;    /* Method not allowed for service. */
    }

    return EC_100;
}

/*
 * ICAPリクエスト Encapsulatedヘッダ書式検査
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *   EC_100 : 書式検査ＯＫ
 *   EC_400 : 書式検査ＮＧ
 */
static int check_request(ci_request_t *req)
{

    /*
     * req->entities には Encapsulated ヘッダの解析結果が格納される
     * ex) Encapsulated: req-hdr=0, req-body=147 の場合、
     *   req->entities[0]  ->  req-hdr=0 の解析内容
     *   req->entities[1]  ->  req-body=147 の解析内容
     */

    /*Check encapsulated header*/
    if (req->entities[0] == NULL && req->type != ICAP_OPTIONS) /*No encapsulated header*/
        return EC_400;

    ci_debug_printf(6, "\n type:%d Entities: %d %d %d %d \n",
                    req->type,
                    req->entities[0] ? req->entities[0]->type : -1,
                    req->entities[1] ? req->entities[1]->type : -1,
                    req->entities[2] ? req->entities[2]->type : -1,
                    req->entities[3] ? req->entities[3]->type : -1
                   );

    /* Encapsulated ヘッダ解析結果の検査 */

    /*
     * REQMOD で正常とするパターンは以下
     * - req-hdr=xxx, req-body=xxx
     * - req-hdr=xxx, null-body=xxx
     * - req-body=xxx
     *
     * 以下は、RFCでは許容されるが、c-icapでは許容していない
     * - null-body=xxx
     */
    if (req->type == ICAP_REQMOD) {
        if (req->entities[2] != NULL)
            return EC_400;
        else if (req->entities[1] != NULL) {
            if (req->entities[0]->type != ICAP_REQ_HDR)
                return EC_400;
            if (req->entities[1]->type != ICAP_REQ_BODY && req->entities[1]->type != ICAP_NULL_BODY)
                return EC_400;
        } else {
            /*If it has only one encapsulated object it must be body data*/
            if (req->entities[0]->type != ICAP_REQ_BODY)
                return EC_400;

        }

    /*
     * RESPMOD で正常とするパターンは以下
     * - [reqhdr] [reshdr] resbody
     * - req-hdr=xxx, res-hdr=xxx, res-body=xxx
     * - req-hdr=xxx, res-hdr=xxx, null-body=xxx
     * - req-hdr=xxx, res-body=xxx
     * - req-hdr=xxx, null-body=xxx
     * - res-hdr=xxx, res-body=xxx
     * - res-hdr=xxx, null-body=xxx
     * - res-body=xxx

     *
     * 以下は、RFCでは許容されるが、c-icapでは許容していない
     * - null-body=xxx
     */
    } else if (req->type == ICAP_RESPMOD) {
        if (req->entities[3] != NULL)
            return EC_400;
        else if (req->entities[2] != NULL) {
            assert(req->entities[0]);
            assert(req->entities[1]);
            if (req->entities[0]->type != ICAP_REQ_HDR)
                return EC_400;
            if (req->entities[1]->type != ICAP_RES_HDR)
                return EC_400;
            if (req->entities[2]->type != ICAP_RES_BODY && req->entities[2]->type != ICAP_NULL_BODY)
                return EC_400;
        } else if (req->entities[1] != NULL) {
            if (req->entities[0]->type != ICAP_RES_HDR && req->entities[0]->type != ICAP_REQ_HDR)
                return EC_400;
            if (req->entities[1]->type != ICAP_RES_BODY && req->entities[1]->type != ICAP_NULL_BODY)
                return EC_400;
        } else {
            /*If it has only one encapsulated object it must be body data*/
            if (req->entities[0]->type != ICAP_RES_BODY)
                return EC_400;
        }
    }
    return EC_100;
}

/*
 * ICAPリクエストヘッダ解析処理
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *   EC_XXX
 */
static int parse_header(ci_request_t * req)
{
    int i, request_status = EC_100, result;
    ci_headers_list_t *h;
    char *val;

    h = req->request_header;
    /* ICAPリクエストヘッダ受信 */
    if ((request_status = ci_read_icap_header(req, h, TIMEOUT)) != EC_100)
        return request_status;

    /* ヘッダ情報を内部オブジェクト(h->headers)に格納 */
    if ((request_status = ci_headers_unpack(h)) != EC_100)
        return request_status;

    /* ICAPリクエストライン解析 */
    if ((request_status = parse_request(req, h->headers[0])) != EC_100)
        return request_status;

    /* ICAPヘッダ解析 */
    for (i = 1; i < h->used && request_status == EC_100; i++) {
        if (strncasecmp("Preview:", h->headers[i], 8) == 0) {
            val = h->headers[i] + 8;
            for (; isspace(*val) && *val != '\0'; ++val);
            errno = 0;
            result = strtol(val, NULL, 10);
            if (errno != EINVAL && errno != ERANGE) {
                req->preview = result;
                if (result >= 0) {
                    /* ★ メモリ確保失敗時のエラーハンドル追加 */
                    // ci_buf_reset_size(&(req->preview_data), result + 64);
                    if (ci_buf_reset_size(&(req->preview_data), result + 64) == 0) {
                        request_status = EC_500;
                    }
                }
            }
        } else if (strncasecmp("Encapsulated:", h->headers[i], 13) == 0)
            request_status = process_encapsulated(req, h->headers[i]);
        else if (strncasecmp("Connection:", h->headers[i], 11) == 0) {
            val = h->headers[i] + 11;
            for (; isspace(*val) && *val != '\0'; ++val);
            /*             if(strncasecmp(val,"keep-alive",10)==0)*/
            if (strncasecmp(val, "close", 5) == 0)
                req->keepalive = 0;
            /*else the default behaviour of keepalive ..... */
        } else if (strncasecmp("Allow:", h->headers[i], 6) == 0) {
            if (strstr(h->headers[i]+6, "204"))
                req->allow204 = 1;
            if (strstr(h->headers[i]+6, "206"))
                req->allow206 = 1;
        }
    }

    if (request_status != EC_100)
        return request_status;

    /* Encapsulatedヘッダ書式検査 */
    return check_request(req);
}


/*
 * カプセル化ヘッダ(HTTPリクエストヘッダ or HTTPレスポンスヘッダ)解析処理
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *   EC_XXX
 */
static int parse_encaps_headers(ci_request_t * req)
{
    int size, i, request_status = 0;
    ci_encaps_entity_t *e = NULL;
    for (i = 0; (e = req->entities[i]) != NULL; i++) {
        /* 以降はボディデータ */
        if (e->type > ICAP_RES_HDR)   //res_body,req_body or opt_body so the end of the headers.....process_encapsulated
            return EC_100;

        /* カプセル化ヘッダの後ろには最低限ボディエンティティを期待する */
        if (req->entities[i + 1] == NULL)
            return EC_400;

        size = req->entities[i + 1]->start - e->start;

        /* Encapsulated ヘッダで指定されたバイト分のみリクエスト読み込み */
        if ((request_status =
                    read_encaps_header(req, (ci_headers_list_t *) e->entity,
                                       size)) != EC_100)
            return request_status;

        /* ヘッダ情報を内部オブジェクト(h->headers)に格納 */
        if ((request_status =
                    ci_headers_unpack((ci_headers_list_t *) e->entity)) != EC_100)
            return request_status;
    }
    return EC_100;
}

/*
  In read_preview_data I must check if readed data are more than
  those client said in preview header
*/
/*
 * Preview データの読み込み
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *   CI_OK      : 処理正常（Preview で残ボディあり）
 *   CI_EOF     : 処理正常（Preview で全ボディ受信済み）
 *   CI_ERROR   : 処理異常
 */
static int read_preview_data(ci_request_t * req)
{
    int ret;
    char *wdata;

    req->current_chunk_len = 0;
    req->chunk_bytes_read = 0;
    req->write_to_module_pending = 0;

    /* ボディデータ受信 */
    if (req->pstrblock_read_len == 0) {
        if (wait_for_data(req->connection, TIMEOUT, ci_wait_for_read) < 0)
            return CI_ERROR;

        if (net_data_read(req) == CI_ERROR)
            return CI_ERROR;
    }

    /* チャンクデータ解析 */
    /* 溢れデータがあれば先に解析して追加分のボディデータを受信 */
    do {
        do {
            if ((ret = parse_chunk_data(req, &wdata)) == CI_ERROR) {
                ci_debug_printf(1,
                                "Error parsing chunks, current chunk len: %d readed:%d, str:%s\n",
                                req->current_chunk_len,
                                req->chunk_bytes_read, req->pstrblock_read);
                return CI_ERROR;
            }
            /* req->preview_data に受信データを格納 */
            if (ci_buf_write
                    (&(req->preview_data), wdata,
                     req->write_to_module_pending) < 0)
                return CI_ERROR;
            req->write_to_module_pending = 0;

            /* 0バイトチャンクまで受信した */
            if (ret == CI_EOF) {
                req->pstrblock_read = NULL;
                req->pstrblock_read_len = 0;
                if (req->eof_received)
                    return CI_EOF;
                return CI_OK;
            }
        } while (ret != CI_NEEDS_MORE);

        /* ボディデータ受信 */
        if (wait_for_data(req->connection, TIMEOUT, ci_wait_for_read) < 0)
            return CI_ERROR;
        if (net_data_read(req) == CI_ERROR)
            return CI_ERROR;
    } while (1);

    return CI_ERROR;
}

/*
 * ICAPレスポンス処理（ICAPレスポンスラインのみ）
 *   - 主に "100 Continue" 応答用
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *   int            ec  : 応答コード
 *
 * 復帰値
 *   なし
 */
static void ec_responce_simple(ci_request_t * req, int ec)
{
    char buf[256];
    int len;
    snprintf(buf, 256, "ICAP/1.0 %d %s\r\n\r\n",
             ci_error_code(ec), ci_error_code_string(ec));
    buf[255] = '\0';
    len = strlen(buf);
    ci_connection_write(req->connection, buf, len, TIMEOUT);
    req->bytes_out += len;
    req->return_code = ec;
}

/*
 * ICAPレスポンス処理（ICAPレスポンスライン＋ICAPヘッダのみ）
 *   - 主に エラー応答や204応答用
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *   int            ec  : 応答コード
 *
 * 復帰値
 *   >0 : 応答処理正常(応答サイズ)
 *   -1 : 応答処理異常
 */
static int ec_responce(ci_request_t * req, int ec)
{
    char buf[256];
    ci_service_xdata_t *srv_xdata = NULL;
    int len, allow204to200OK = 0;
    if (req->current_service_mod)
        srv_xdata = service_data(req->current_service_mod);

    /* 応答ヘッダオブジェクト初期化 */
    ci_headers_reset(req->response_header);

    /* 204応答を200応答にする設定の場合 */
    if (ec == EC_204 && ALLOW204_AS_200OK_ZERO_ENCAPS) {
        allow204to200OK = 1;
        ec = EC_200;
    }

    /* ICAPレスポンスライン */
    snprintf(buf, 256, "ICAP/1.0 %d %s",
             ci_error_code(ec), ci_error_code_string(ec));
    ci_headers_add(req->response_header, buf);

    /* ICAPレスポンスヘッダ */
    ci_headers_add(req->response_header, "Server: C-ICAP/" VERSION);
    if (req->keepalive)
        ci_headers_add(req->response_header, "Connection: keep-alive");
    else
        ci_headers_add(req->response_header, "Connection: close");

    if (srv_xdata) {
        ci_service_data_read_lock(srv_xdata);
        ci_headers_add(req->response_header, srv_xdata->ISTag);
        ci_service_data_read_unlock(srv_xdata);
    }
    if (!ci_headers_is_empty(req->xheaders)) {
        ci_headers_addheaders(req->response_header, req->xheaders);
    }
    if (allow204to200OK) {
        if (req->type == ICAP_REQMOD)
            ci_headers_add(req->response_header, "Encapsulated: req-hdr=0, null-body=0");
        else
            ci_headers_add(req->response_header, "Encapsulated: res-hdr=0, null-body=0");
    }
    /*
      TODO: Release req->entities (ci_request_release_entity())
     */
#if 0
    /* ci_request_reset() @ request_common.c より */
    int i;

    for (i = 0; req->entities[i] != NULL; i++) {
        ci_request_release_entity(req, i);
    }

    /*Reset the encapsulated response or request headers*/
    if (req->trash_entities[ICAP_REQ_HDR] &&
            req->trash_entities[ICAP_REQ_HDR]->entity)
        ci_headers_reset((ci_headers_list_t *)req->trash_entities[ICAP_REQ_HDR]->entity);
    if (req->trash_entities[ICAP_RES_HDR] &&
            req->trash_entities[ICAP_RES_HDR]->entity)
        ci_headers_reset((ci_headers_list_t *)req->trash_entities[ICAP_RES_HDR]->entity);
#endif

    /* 応答ヘッダオブジェクトから応答データ生成 */
    ci_headers_pack(req->response_header);
    req->return_code = ec;

    /* 応答データをクライアントへ送信 */
    len = ci_connection_write(req->connection,
                              req->response_header->buf, req->response_header->bufused,
                              TIMEOUT);

    /*We are finishing sending*/
    req->status = SEND_EOF;

    if (len < 0)
        return -1;

    req->bytes_out += len;
    return len;
}

extern char MY_HOSTNAME[];
/*
 * ICAPレスポンスヘッダ生成
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *   1（常時）
 */
static int mk_responce_header(ci_request_t * req)
{
    ci_headers_list_t *head;
    ci_encaps_entity_t **e_list;
    ci_service_xdata_t *srv_xdata;
    char buf[512];
    /* サービス拡張オブジェクトの有無は呼び出しもとでチェック済み */
    srv_xdata = service_data(req->current_service_mod);
    ci_headers_reset(req->response_header);
    head = req->response_header;
    assert(req->return_code >= EC_100 && req->return_code < EC_MAX);
    snprintf(buf, 512, "ICAP/1.0 %d %s",
             ci_error_code(req->return_code), ci_error_code_string(req->return_code));
    ci_headers_add(head, buf);
    ci_headers_add(head, "Server: C-ICAP/" VERSION);
    if (req->keepalive)
        ci_headers_add(head, "Connection: keep-alive");
    else
        ci_headers_add(head, "Connection: close");
    ci_service_data_read_lock(srv_xdata);
    ci_headers_add(head, srv_xdata->ISTag);
    ci_service_data_read_unlock(srv_xdata);
    if (!ci_headers_is_empty(req->xheaders)) {
        ci_headers_addheaders(head, req->xheaders);
    }

    e_list = req->entities;
    if (req->type == ICAP_RESPMOD) {
        if (e_list[0]->type == ICAP_REQ_HDR) {
            ci_request_release_entity(req, 0);
            e_list[0] = e_list[1];
            e_list[1] = e_list[2];
            e_list[2] = NULL;
        }
    }

    snprintf(buf, 512, "Via: ICAP/1.0 %s (C-ICAP/" VERSION " %s )",
             MY_HOSTNAME,
             (req->current_service_mod->mod_short_descr ? req->
              current_service_mod->mod_short_descr : req->current_service_mod->
              mod_name));
    buf[511] = '\0';
    /*Here we must append it to an existsing Via header not just add a new header */
    if (req->type == ICAP_RESPMOD) {
        ci_http_response_add_header(req, buf);
    } else if (req->type == ICAP_REQMOD) {
        ci_http_request_add_header(req, buf);
    }

    /* 応答データ生成 */
    ci_response_pack(req);
    return 1;
}


/****************************************************************/
/* New  functions to send responce */

const char *eol_str = "\r\n";
const char *eof_str = "0\r\n\r\n";


/*
 * ICAPレスポンス送信処理
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *    0             : 送信データないため送信なし
 *   >0             : 送信成功（送信サイズ）
 *   CI_ERROR(-1)   : 送信異常
 */
static int send_current_block_data(ci_request_t * req)
{
    int bytes;
    if (req->remain_send_block_bytes == 0)
        return 0;

    /*
     * write() でレスポンス送信
     * 非SSL通信なら ci_connection_write_nonblock() は write() == 0 の場合に
     * byte = -1 で復帰するため、bytes == 0 にはならない
     */
    if ((bytes =
                ci_connection_write_nonblock(req->connection, req->pstrblock_responce,
                        req->remain_send_block_bytes)) < 0) {
        ci_debug_printf(5, "Error writing to socket (errno:%d, bytes:%d. string:\"%s\")", errno, req->remain_send_block_bytes, req->pstrblock_responce);
        return CI_ERROR;
    }

    /*
         if (bytes == 0) {
             ci_debug_printf(5, "Can not write to the client. Is the connection closed?");
             return CI_ERROR;
         }
    */

    req->pstrblock_responce += bytes;
    req->remain_send_block_bytes -= bytes;
    req->bytes_out += bytes;
    if (req->status >= SEND_HEAD1 &&  req->status <= SEND_HEAD3)
        req->http_bytes_out +=bytes;
    return req->remain_send_block_bytes;
}


/*
 * チャンクボディ生成処理
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *  CI_OK   : チャンクブロックを生成
 *  CI_EOF  : チャンク終端行を生成
 *            または、チャンク化対象ボディデータなし
 */
static int format_body_chunk(ci_request_t * req)
{
    int def_bytes;
    char *wbuf = NULL;
    char tmpbuf[EXTRA_CHUNK_SIZE];

    /* チャンク化対象ボディデータなし */
    if (!req->responce_hasbody)
        return CI_EOF;
    if (req->remain_send_block_bytes > 0) {
        assert(req->remain_send_block_bytes <= MAX_CHUNK_SIZE);

        /*The data are not written yet but I hope there is not any problem.
          It is difficult to compute data sent */
        req->http_bytes_out += req->remain_send_block_bytes;
        req->body_bytes_out += req->remain_send_block_bytes;

        /* チャンクブロックの最大サイズ位置に \r\n を置く */
        wbuf = req->wbuf + EXTRA_CHUNK_SIZE + req->remain_send_block_bytes;
        /*Put the "\r\n" sequence at the end of chunk */
        *(wbuf++) = '\r';
        *wbuf = '\n';
        /* チャンクサイズ行生成 */
        def_bytes =
            snprintf(tmpbuf, EXTRA_CHUNK_SIZE, "%x\r\n",
                     req->remain_send_block_bytes);
        /* チャンク行をボディデータの先頭に書き込み */
        wbuf = req->wbuf + EXTRA_CHUNK_SIZE - def_bytes;      /*Copy the chunk define in the beggining of chunk ..... */
        memcpy(wbuf, tmpbuf, def_bytes);
        req->pstrblock_responce = wbuf;
        req->remain_send_block_bytes += def_bytes + 2;
    } else if (req->remain_send_block_bytes == CI_EOF) {
        if (req->return_code == EC_206 && req->i206_use_original_body >= 0) {
            def_bytes = sprintf(req->wbuf, "0; use-original-body=%" PRId64 "\r\n\r\n",
                                req->i206_use_original_body );
            req->pstrblock_responce = req->wbuf;
            req->remain_send_block_bytes = def_bytes;
        } else {
            /* チャンク終端行 */
            strcpy(req->wbuf, "0\r\n\r\n");
            req->pstrblock_responce = req->wbuf;
            req->remain_send_block_bytes = 5;
        }
        return CI_EOF;
    }
    return CI_OK;
}



/*
 * ICAPリクエスト内のカプセル化ボディ有無検査
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *  0   : ボディなし
 *  1   : ボディあり
 */
static int resp_check_body(ci_request_t * req)
{
    int i;
    ci_encaps_entity_t **e = req->entities;
    for (i = 0; e[i] != NULL; i++)
        if (e[i]->type == ICAP_NULL_BODY)
            return 0;
    return 1;
}

/*
The
if((ret=send_current_block_data(req))!=0)
  return ret;

must called after this function....
*/

/*
 * ICAPレスポンス送信状態の更新
 *
 * レスポンス送信状態
 *   SEND_NOTHING   : 未送信
 *   SEND_RESPHEAD  : ICAPレスポンスヘッダ送信
 *   SEND_HEAD1     : req->entities[0] の送信
 *   SEND_HEAD2     : req->entities[1] の送信
 *   SEND_HEAD3     : req->entities[2] の送信
 *   SEND_BODY      : HTTPボディ送信
 *   SEND_EOF       : 送信完了
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *   CI_OK      : 処理正常（残レスポンスデータあり）
 *   CI_EOF     : 処理正常（全レスポンスデータ送信済み）
 *   CI_ERROR   : 処理異常
 */
static int update_send_status(ci_request_t * req)
{
    int i, status;
    ci_encaps_entity_t *e;

    if (req->status == SEND_NOTHING) { //If nothing has send start sending....
        /* ICAPレスポンスヘッダ生成 */
        if (!mk_responce_header(req)) {
            ci_debug_printf(1, "Error constructing the responce headers!\n");
            return CI_ERROR;
        }
        req->responce_hasbody = resp_check_body(req);

        req->pstrblock_responce = req->response_header->buf;
        req->remain_send_block_bytes = req->response_header->bufused;
        req->status = SEND_RESPHEAD;
        ci_debug_printf(9, "Going to send response headers\n");
        return CI_OK;
    }

    if (req->status == SEND_EOF) {
        ci_debug_printf(9, "The req->status is EOF (remain to send bytes:%d)\n",
                        req->remain_send_block_bytes);
        if (req->remain_send_block_bytes == 0)
            return CI_EOF;
        else
            return CI_OK;
    }
    if (req->status == SEND_BODY) {
        ci_debug_printf(9, "Send status is SEND_BODY return\n");
        return CI_OK;
    }

    if ((status = req->status) < SEND_HEAD3) {
        status++;
    }

    if (status > SEND_RESPHEAD && status < SEND_BODY) {        /*status is SEND_HEAD1 SEND_HEAD2 or SEND_HEAD3    */
        i = status - SEND_HEAD1;      /*We have to send next headers block .... */
        if ((e = req->entities[i]) != NULL
                && (e->type == ICAP_REQ_HDR || e->type == ICAP_RES_HDR)) {

            req->pstrblock_responce = ((ci_headers_list_t *) e->entity)->buf;
            req->remain_send_block_bytes =
                ((ci_headers_list_t *) e->entity)->bufused;

            req->status = status;
            ci_debug_printf(9, "Going to send http headers on entity :%d\n", i);
            return CI_OK;
        } else if (req->responce_hasbody) {   /*end of headers, going to send body now.A body always follows the res_hdr or req_hdr..... */
            req->status = SEND_BODY;
            return CI_OK;
        } else {
            req->status = SEND_EOF;
            req->pstrblock_responce = (char *) NULL;
            req->remain_send_block_bytes = 0;
            return CI_EOF;
        }
    }

    return CI_ERROR;           /*Can not be reached (I thing)...... */
}

/*
 * ボディIOハンドラ(null)
 *   - 処理のないダミーハンドラ
 *
 * 引数
 *   char          *wbuf    : データ送信バッファ
 *   int           *wlen    : 送信サイズ
 *   char          *rbuf    : データ受信バッファ
 *   int           *rlen    : 受信サイズ
 *   int            iseof   : EOFフラグ（1: True, 0: False）
 *   ci_request_t  *req     : リクエストオブジェクト
 *
 * 復帰値
 *   CI_OK      : 正常
 */
static int mod_null_io(char *rbuf, int *rlen, char *wbuf, int *wlen, int iseof,
                       ci_request_t *req)
{
    if (iseof)
        *rlen = CI_EOF;
    else
        *rlen = 0;
    return CI_OK;
}

/*
 * ボディIOハンドラ(echo)
 *   - クライアントからのリクエストボディをそのままレスポンスボディとしてセットする
 *
 * 引数
 *   char          *wbuf    : データ送信バッファ
 *   int           *wlen    : 送信サイズ
 *   char          *rbuf    : データ受信バッファ
 *   int           *rlen    : 受信サイズ
 *   int            iseof   : EOFフラグ（1: True, 0: False）
 *   ci_request_t  *req     : リクエストオブジェクト
 *
 * 復帰値
 *   CI_OK      : 正常
 */
static int mod_echo_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
                       ci_request_t *req)
{
    if (!req->echo_body)
        return CI_ERROR;

    /* 受信データがあれば応答バッファに受信データをセット */
    if (rlen && rbuf) {
        *rlen = ci_ring_buf_write(req->echo_body, rbuf, *rlen);
        if (*rlen < 0)
            return CI_ERROR;
    }

    /* 送信データがあれば要求バッファに送信データをセット */
    if (wbuf && wlen) {
        *wlen = ci_ring_buf_read(req->echo_body, wbuf, *wlen);
        if (*wlen == 0 && req->eof_received)
            *wlen = CI_EOF;
    }

    return CI_OK;
}

/*
 * ボディ送受信処理
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *   int            parse_only  : 0 ) ボディの送受信と解析を行う
 *                                1 ) ボディの解析のみ行う
 *
 * 復帰値
 *   CI_OK      : 正常
 *   CI_ERROR   : 異常
 */
static int get_send_body(ci_request_t * req, int parse_only)
{
    char *wchunkdata = NULL, *rchunkdata = NULL;
    int ret, parse_chunk_ret, has_formated_data = 0;
    int (*service_io) (char *rbuf, int *rlen, char *wbuf, int *wlen, int iseof,
                       ci_request_t *);
    int action = 0, rchunkisfull = 0, service_eof = 0, wbytes, rbytes;
    int lock_status;
    int no_io;

    /* ボディ処理ハンドラの登録 */
    if (parse_only)
        service_io = mod_null_io;
    else if (req->echo_body)
        service_io = mod_echo_io;
    else
        /* サービス固有のボディIOハンドラ */
        service_io = req->current_service_mod->mod_service_io;
    if (!service_io)
        return CI_ERROR;

    req->status = SEND_NOTHING;
    /*in the case we did not have preview data and body is small maybe
       the c-icap already read the body with the headers so do not read
       if there are unparsed bytes in pstrblock buffer

       Preview データがなく、ボディが小さい場合は、c-icapがヘッダと同時に
       ボディも読み込まれる可能性があります。
       そのため、pstrblockバッファに未解析のバイトがある場合はリクエストを
       読み込まないようにしてください。
     */
    if (req->pstrblock_read_len == 0)
        action = ci_wait_for_read;
    do {
        if (action) {
            ci_debug_printf(9, "Going to %s/%s data\n",
                            (action & ci_wait_for_read ? "Read" : "-"),
                            (action & ci_wait_for_write ? "Write" : "-")
                           );
            if ((ret =
                        wait_for_data(req->connection, TIMEOUT,
                                      action)) < 0)
                break;

            /* リクエストボディ受信 */
            if (ret & ci_wait_for_read) {
                if (net_data_read(req) == CI_ERROR)
                    return CI_ERROR;
            }

            /* レスポンスボディ送信 */
            if (ret & ci_wait_for_write) {
                if (!req->data_locked && req->status == SEND_NOTHING) {
                    update_send_status(req);
                }
                if (send_current_block_data(req) == CI_ERROR)
                    return CI_ERROR;
            }
            ci_debug_printf(9,
                            "OK done reading/writing going to process\n");
        }

        if (!req->data_locked && req->remain_send_block_bytes == 0) {
            if (update_send_status(req) == CI_ERROR)
                return CI_ERROR;
            // if(update_send_status == CI_EOF)/*earlier responce from icap server???...*/
        }

        /*Store lock status. If it is changed during module io, we need
          to update send status.*/
        lock_status = req->data_locked;

        /*In the following loop, parses the chunks from readed data
           and try to write data to the service.
           At the same time reads the data from module and try to fill
           the req->wbuf

           以下のループでは、読み込んだデータからチャンクを解析し、
           サービスにデータを書き込もうとします。
           同時にモジュールからデータを読み込み、req->wbuf を埋めようとします。
         */
        if (req->remain_send_block_bytes)
            has_formated_data = 1;
        else
            has_formated_data = 0;
        parse_chunk_ret = 0;
        do {
            /* 受信済みボディデータの解析処理 */
            if (req->pstrblock_read_len != 0
                    && req->write_to_module_pending == 0) {
                if ((parse_chunk_ret =
                            parse_chunk_data(req, &wchunkdata)) == CI_ERROR) {
                    ci_debug_printf(1, "Error parsing chunks!\n");
                    return CI_ERROR;
                }

                if (parse_chunk_ret == CI_EOF)
                    req->eof_received = 1;
            }
            if (wchunkdata && req->write_to_module_pending)
                wbytes = req->write_to_module_pending;
            else
                wbytes = 0;

            if (req->status == SEND_BODY && !service_eof) {
                if (req->remain_send_block_bytes == 0) {
                    /*Leave space for chunk spec.. */
                    rchunkdata = req->wbuf + EXTRA_CHUNK_SIZE;
                    req->pstrblock_responce = rchunkdata;  /*does not needed! */
                    rchunkisfull = 0;
                }
                if ((MAX_CHUNK_SIZE - req->remain_send_block_bytes) > 0
                        && has_formated_data == 0) {
                    rbytes = MAX_CHUNK_SIZE - req->remain_send_block_bytes;
                } else {
                    rchunkisfull = 1;
                    rbytes = 0;
                }
            } else
                rbytes = 0;

            ci_debug_printf(9, "get send body: going to write/read: %d/%d bytes\n", wbytes, rbytes);
            /* ボディ処理ハンドラ呼び出し */
            if ((*service_io)
                    (rchunkdata, &rbytes, wchunkdata, &wbytes, req->eof_received,
                     req) == CI_ERROR)
                return CI_ERROR;
            ci_debug_printf(9, "get send body: written/read: %d/%d bytes (eof: %d)\n", wbytes, rbytes, req->eof_received);
            no_io = (rbytes==0 && wbytes==0);
            if (wbytes) {
                wchunkdata += wbytes;
                req->write_to_module_pending -= wbytes;
            }
            if (rbytes > 0) {
                rchunkdata += rbytes;
                req->remain_send_block_bytes += rbytes;
            } else if (rbytes == CI_EOF)
                service_eof = 1;
        } while (no_io == 0 && req->pstrblock_read_len != 0
                 && parse_chunk_ret != CI_NEEDS_MORE && parse_chunk_ret != CI_EOF && !rchunkisfull);

        action = 0;
        if (!req->write_to_module_pending) {
            action = ci_wait_for_read;
            wchunkdata = NULL;
        }

        if (req->status == SEND_BODY) {
            if (req->remain_send_block_bytes == 0 && service_eof == 1)
                req->remain_send_block_bytes = CI_EOF;
            if (has_formated_data == 0) {
                if (format_body_chunk(req) == CI_EOF)
                    req->status = SEND_EOF;
            }
        }

        if (req->remain_send_block_bytes) {
            action = action | ci_wait_for_write;
        }

    } while ((!req->eof_received || (req->eof_received && req->write_to_module_pending)) && (action || lock_status != req->data_locked));

    if (req->eof_received)
        return CI_OK;

    if (!action) {
        ci_debug_printf(1,
                        "Bug in the service '%s'. "
                        "Please report to the service author!!!!\n"
                        "request status: %d\n"
                        "request data locked?: %d\n"
                        "Write to module pending: %d\n"
                        "Remain send block bytes: %d\n"
                        "Read block len: %d\n",
                        req->service,
                        req->status,
                        req->data_locked,
                        req->write_to_module_pending,
                        req->remain_send_block_bytes,
                        req->pstrblock_read_len
            );
    } else {
        ci_debug_printf(5, "Error reading from network......\n");
    }
    return CI_ERROR;
}


/*Return CI_ERROR on error or CI_OK on success*/
/*
 * 残レスポンスデータ送信処理
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *   CI_OK      : 正常
 *   CI_ERROR   : 異常
 */
static int send_remaining_response(ci_request_t * req)
{
    int ret = 0;
    int (*service_io) (char *rbuf, int *rlen, char *wbuf, int *wlen, int iseof,
                       ci_request_t *);
    if (req->echo_body)
        service_io = mod_echo_io;
    else
        service_io = req->current_service_mod->mod_service_io;

    if (!service_io)
        return CI_ERROR;


    if (req->status == SEND_EOF && req->remain_send_block_bytes == 0) {
        ci_debug_printf(5, "OK sending all data\n");
        return CI_OK;
    }
    do {
        while (req->remain_send_block_bytes > 0) {
            if ((ret =
                        wait_for_data(req->connection, TIMEOUT,
                                      ci_wait_for_write)) < 0) {
                ci_debug_printf(3,
                                "Timeout sending data. Ending .......\n");
                return CI_ERROR;
            }
            /* データ送信 */
            if (send_current_block_data(req) == CI_ERROR)
                return CI_ERROR;
        }

        if (req->status == SEND_BODY && req->remain_send_block_bytes == 0) {
            req->pstrblock_responce = req->wbuf + EXTRA_CHUNK_SIZE;  /*Leave space for chunk spec.. */
            req->remain_send_block_bytes = MAX_CHUNK_SIZE;
            ci_debug_printf(9, "rest response: going to read: %d bytes\n", req->remain_send_block_bytes);
            /* ボディ処理ハンドラ呼び出し */
            service_io(req->pstrblock_responce,
                       &(req->remain_send_block_bytes), NULL, NULL, 1, req);
            ci_debug_printf(9, "rest response: read: %d bytes\n", req->remain_send_block_bytes);
            if (req->remain_send_block_bytes == CI_ERROR)    /*CI_EOF of CI_ERROR, stop sending.... */
                return CI_ERROR;
            if (req->remain_send_block_bytes == 0)
                break;

            if ((ret = format_body_chunk(req)) == CI_EOF) {
                req->status = SEND_EOF;
            }
        }

    } while ((ret = update_send_status(req)) >= 0);    /*CI_EOF is < 0 */

    if (ret == CI_ERROR)
        return ret;

    return CI_OK;
}

/*
 * OPTIONS 応答処理
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *   なし
 */
static void options_responce(ci_request_t * req)
{
    char buf[MAX_HEADER_SIZE + 1];
    const char *str;
    ci_headers_list_t *head;
    ci_service_xdata_t *srv_xdata;
    unsigned int xopts;
    int preview, allow204, allow206, max_conns, xlen;
    int hastransfer = 0;
    int ttl;
    req->return_code = EC_200;
    head = req->response_header;
    /* サービス拡張オブジェクトの有無は呼び出しもとでチェック済み */
    srv_xdata = service_data(req->current_service_mod);
    ci_headers_reset(head);
    /* サービス個別のOPTIONS処理ハンドラ呼び出し */
    if (run_services_option_handlers(srv_xdata, req) != CI_OK)
        ci_headers_add(head, "ICAP/1.0 500 Server Error");
    else
        ci_headers_add(head, "ICAP/1.0 200 OK");
    strcpy(buf, "Methods: ");
    if (ci_method_support(req->current_service_mod->mod_type, ICAP_RESPMOD)) {
        strcat(buf, "RESPMOD");
        if (ci_method_support
                (req->current_service_mod->mod_type, ICAP_REQMOD)) {
            strcat(buf, ", REQMOD");
        }
    } else {                   /*At least one method must supported. A check for error must exists here..... */
        strcat(buf, "REQMOD");
    }

    ci_headers_add(head, buf);
    snprintf(buf, MAX_HEADER_SIZE, "Service: C-ICAP/" VERSION " server - %s",
             ((str =
                   req->current_service_mod->mod_short_descr) ? str : req->
              current_service_mod->mod_name));
    buf[MAX_HEADER_SIZE] = '\0';
    ci_headers_add(head, buf);

    ci_service_data_read_lock(srv_xdata);
    ci_headers_add(head, srv_xdata->ISTag);
    if (srv_xdata->TransferPreview[0] != '\0' && srv_xdata->preview_size >= 0) {
        ci_headers_add(head, srv_xdata->TransferPreview);
        hastransfer++;
    }
    if (srv_xdata->TransferIgnore[0] != '\0') {
        ci_headers_add(head, srv_xdata->TransferIgnore);
        hastransfer++;
    }
    if (srv_xdata->TransferComplete[0] != '\0') {
        ci_headers_add(head, srv_xdata->TransferComplete);
        hastransfer++;
    }
    /*If none of the Transfer-* headers configured but preview configured  send all requests*/
    if (!hastransfer && srv_xdata->preview_size >= 0)
        ci_headers_add(head, "Transfer-Preview: *");
    /*Get service options before close the lock.... */
    xopts = srv_xdata->xopts;
    preview = srv_xdata->preview_size;
    allow204 = srv_xdata->allow_204;
    allow206 = srv_xdata->allow_206;
    max_conns = srv_xdata->max_connections;
    ttl = srv_xdata->options_ttl;
    ci_service_data_read_unlock(srv_xdata);

    ci_debug_printf(5, "Options response: \n"
                    " Preview: %d\n"
                    " Allow 204: %s\n"
                    " Allow 206: %s\n"
                    " TransferPreview: \"%s\"\n"
                    " TransferIgnore: %s\n"
                    " TransferComplete: %s\n"
                    " Max-Connections: %d\n",
                    preview,(allow204?"yes":"no"),
                    (allow206?"yes":"no"),
                    srv_xdata->TransferPreview,
                    srv_xdata->TransferIgnore,
                    srv_xdata->TransferComplete,
                    max_conns
                   );

    /* ci_headers_add(head, "Max-Connections: 20"); */
    if (ttl > 0) {
        sprintf(buf, "Options-TTL: %d", ttl);
        ci_headers_add(head, buf);
    } else
        ci_headers_add(head, "Options-TTL: 3600");
    strcpy(buf, "Date: ");
    ci_strtime_rfc822(buf + strlen(buf));
    ci_headers_add(head, buf);
    if (preview >= 0) {
        sprintf(buf, "Preview: %d", srv_xdata->preview_size);
        ci_headers_add(head, buf);
    }
    if (max_conns >= 0) {
        sprintf(buf, "Max-Connections: %d", max_conns);
        ci_headers_add(head, buf);
    }
    if (allow204 && allow206) {
        ci_headers_add(head, "Allow: 204, 206");
    } else if (allow204) {
        ci_headers_add(head, "Allow: 204");
    }
    if (xopts) {
        strcpy(buf, "X-Include: ");
        xlen = 11;            /*sizeof("X-Include: ") */
        if ((xopts & CI_XCLIENTIP)) {
            strcat(buf, "X-Client-IP");
            xlen += sizeof("X-Client-IP");
        }
        if ((xopts & CI_XSERVERIP)) {
            if (xlen > 11) {
                strcat(buf, ", ");
                xlen += 2;
            }
            strcat(buf, "X-Server-IP");
            xlen += sizeof("X-Server-IP");
        }
        if ((xopts & CI_XSUBSCRIBERID)) {
            if (xlen > 11) {
                strcat(buf, ", ");
                xlen += 2;
            }
            strcat(buf, "X-Subscriber-ID");
            xlen += sizeof("X-Subscriber-ID");
        }
        if ((xopts & CI_XAUTHENTICATEDUSER)) {
            if (xlen > 11) {
                strcat(buf, ", ");
                xlen += 2;
            }
            strcat(buf, "X-Authenticated-User");
            xlen += sizeof("X-Authenticated-User");
        }
        if ((xopts & CI_XAUTHENTICATEDGROUPS)) {
            if (xlen > 11) {
                strcat(buf, ", ");
                xlen += 2;
            }
            strcat(buf, "X-Authenticated-Groups");
            xlen += sizeof("X-Authenticated-Groups");
        }
        if (xlen > 11)
            ci_headers_add(head, buf);
    }
    if (!ci_headers_is_empty(req->xheaders)) {
        ci_headers_addheaders(head, req->xheaders);
    }
    /* ICAPレスポンスデータ生成 */
    ci_response_pack(req);

    req->pstrblock_responce = head->buf;
    req->remain_send_block_bytes = head->bufused;

    do {
        /* 書き込み待機 */
        if ((wait_for_data(req->connection, TIMEOUT, ci_wait_for_write))
                < 0) {
            ci_debug_printf(3, "Timeout sending data. Ending .......\n");
            return;
        }
        /* クライアントへレスポンス送信 */
        if (send_current_block_data(req) == CI_ERROR) {
            ci_debug_printf(3, "Error sending data. Ending .....\n");
            return;
        }
    } while (req->remain_send_block_bytes > 0);

//     if(responce_body)
//        send_body_responce(req,responce_body);

}

/*Read preview data, call preview handler and respond with error,  "204" or
  "100 Continue" if required.
  Returns:
  - CI_OK on success and 100 Continue,
  - CI_EOF on ieof chunk response (means all body data received,
     inside preview, no need to read more data from the client)
  - CI_ERROR on error
*/
/*
 * Preview データの読み取りとレスポンス処理
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *   CI_OK      : Preview 処理成功
 *   CI_EOF     : Preview サイズ内で全ボディ受信
 *   CI_ERROR   : 処理異常
 */
static int do_request_preview(ci_request_t *req)
{
    int preview_read_status;
    int res;

    ci_debug_printf(8,"Read preview data if there are and process request\n");

    /*read_preview_data returns CI_OK, CI_EOF or CI_ERROR */
    if (!req->hasbody)
        preview_read_status = CI_EOF;
    else if ((preview_read_status = read_preview_data(req)) == CI_ERROR) {
        ci_debug_printf(5,
                        "An error occured while reading preview data (propably timeout)\n");
        req->keepalive = 0;
        ec_responce(req, EC_408);
        return CI_ERROR;
    }

    /*
     * サービス固有の Preview 処理ハンドラ呼び出し
     * ハンドラ登録なければ "100 Continue" 応答
     */
    if (!req->current_service_mod->mod_check_preview_handler) {
        /*We have not a preview data handler. We are responding with "100 Continue"
          assuming that the service needs to process all data.
          The preview data are stored in req->preview_data.buf, if the service needs them.
         */
        ci_debug_printf(3, "Preview request but no preview data handler. Respond with \"100 Continue\"\n");
        res =  CI_MOD_CONTINUE;
    } else {
        /*We have a preview handler and we are going to call it*/
        res = req->current_service_mod->mod_check_preview_handler(
                  req->preview_data.buf, req->preview_data.used, req);
    }

    /* 204応答 */
    if (res == CI_MOD_ALLOW204) {
        if (ec_responce(req, EC_204) < 0) {
            req->keepalive = 0; /*close the connection*/
            return CI_ERROR;
        }

        ci_debug_printf(5,"Preview handler return allow 204 response\n");
        /*we are finishing here*/
        return CI_OK;
    }

    /* 206応答 */
    if (res == CI_MOD_ALLOW206 && req->allow206) {
        req->return_code = EC_206;
        ci_debug_printf(5,"Preview handler return 206 response\n");
        return CI_OK;
    }

    /*The CI_MOD_CONTINUE is the only remaining valid answer */
    if (res != CI_MOD_CONTINUE) {
        ci_debug_printf(5, "An error occured in preview handler!"
                        " return code: %d , req->allow204=%d, req->allow206=%d\n",
                        res, req->allow204, req->allow206);
        req->keepalive = 0;
        ec_responce(req, EC_500);
        return CI_ERROR;
    }

    /* res == CI_MOD_CONTINUE */

    if (preview_read_status != CI_EOF)  {
        ec_responce_simple(req, EC_100);     /*if 100 Continue and not "0;ieof"*/
    }
    /* else 100 Continue and "0;ieof" received. Do not send "100 Continue"*/

    ci_debug_printf(5,"Preview handler %s\n",
                    (preview_read_status == CI_EOF ? "receives all body data" : "continue reading more body data"));

    return preview_read_status;
}

/*
   Call the preview handler in the case there is not preview request.

*/
/*
 * 非 Preview 時のボディデータの読み取りとレスポンス処理
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *   CI_OK      : Preview 処理成功
 *   CI_EOF     : Preview サイズ内で全ボディ受信
 *   CI_ERROR   : 処理異常
 */
static int do_fake_preview(ci_request_t * req)
{
    int res;
    /*We are outside preview. The preview handler will be called but it needs
      special handle.
      Currently the preview data handler called with no preview data.In the future we
      should add code to read data from client and pass them to the service.
      Also in the future the service should not need to know if preview supported
      by the client or not
    */

    if (!req->current_service_mod->mod_check_preview_handler) {
        req->return_code = req->hasbody ? EC_100 : EC_200;
        return CI_OK; /*do nothing*/
    }

    ci_debug_printf(8,"Preview does not supported. Call the preview handler with no preview data.\n");
    /* サービス固有のPreview 処理ハンドラ呼び出し */
    res = req->current_service_mod->mod_check_preview_handler(NULL, 0, req);

    /*We are outside preview. The client should support allow204 outside preview
      to support it.
     */
    /* サービスとクライアントの両方が204応答サポートの場合 */
    if (res == CI_MOD_ALLOW204 && req->allow204) {
        ci_debug_printf(5,"Preview handler return allow 204 response, and allow204 outside preview supported\n");
        if (ec_responce(req, EC_204) < 0) {
            req->keepalive = 0; /*close the connection*/
            return CI_ERROR;
        }

        /*And now parse body data we have read and data the client going to send us,
          but do not pass them to the service (second argument of the get_send_body)

          読み込んだボディデータとクライアントが送信しようとしているデータを解析するが
          それらのデータをサービスには渡さない。(get_send_bodyの第二引数)
        */
        if (req->hasbody) {
            res = get_send_body(req, 1);
            if (res == CI_ERROR)
                return res;
        }
        req->return_code = EC_204;
        return CI_OK;
    }

    /* サービスのみ204応答サポートの場合 */
    if (res == CI_MOD_ALLOW204) {
        if (req->hasbody) {
            ci_debug_printf(5,"Preview handler return allow 204 response, allow204 outside preview does NOT supported, and body data\n");
            /*
             * ICAPリクエストボディあり かつ、
             *   - FAKE_ALLOW204 設定有効の場合、200応答
             *   - FAKE_ALLOW204 設定無効の場合、500応答(本関数の最後部の処理)
             */
            if (FAKE_ALLOW204) {
                ci_debug_printf(5,"Fake allow204 supported, echo data back\n");
                req->echo_body = ci_ring_buf_new(32768);
                req->return_code = EC_100;
                return CI_OK;
            }
        } else {
            ci_debug_printf(5,"Preview handler return allow 204 response, allow204 outside preview does NOT supported, but no body data\n");
            /*Just copy http headers to icap response*/
            req->return_code = EC_200;
            return CI_OK;
        }
    }

    /* サービスとクライアントの両方が206応答サポートの場合 */
    if (res == CI_MOD_ALLOW206 && req->allow204 && req->allow206) {
        ci_debug_printf(5,"Preview handler return allow 204 response, allow204 outside preview and allow206 supported by t");
        req->return_code = EC_206;
        return CI_OK;
    }

    if (res == CI_MOD_CONTINUE) {
        req->return_code = req->hasbody ? EC_100 : EC_200;
        return CI_OK;
    }

    ci_debug_printf(1, "An error occured in preview handler (outside preview)!"
                    " return code: %d, req->allow204=%d, req->allow206=%d\n",
                    res, req->allow204, req->allow206);
    req->keepalive = 0;
    ec_responce(req, EC_500);
    return CI_ERROR;
}

/*
  Return CI_ERROR or CI_OK
*/
/*
 * データ取得完了処理
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *   CI_OK      : 処理正常
 *   CI_ERROR   : 処理異常
 */
static int do_end_of_data(ci_request_t * req)
{
    int res;

    if (!req->current_service_mod->mod_end_of_data_handler)
        return CI_OK; /*Nothing to do*/

    /* サービス固有のデータ取得完了ハンドラ呼び出し */
    res = req->current_service_mod->mod_end_of_data_handler(req);
    /*
         while( req->current_service_mod->mod_end_of_data_handler(req)== CI_MOD_NOT_READY){
         //can send some data here .........
         }
    */
    if (res == CI_MOD_ALLOW204 && req->allow204 && !ci_req_sent_data(req)) {
        if (ec_responce(req, EC_204) < 0) {
            ci_debug_printf(5, "An error occured while sending allow 204 response\n");
            return CI_ERROR;
        }

        return CI_OK;
    }

    if (res == CI_MOD_ALLOW206 && req->allow204 && req->allow206 && !ci_req_sent_data(req)) {
        req->return_code = EC_206;
        return CI_OK;
    }

    if (res != CI_MOD_DONE) {
        ci_debug_printf(1, "An error occured in end-of-data handler !"
                        "return code : %d, req->allow204=%d, req->allow206=%d\n",
                        res, req->allow204, req->allow206);

        if (!ci_req_sent_data(req)) {
            req->keepalive = 0;
            ec_responce(req, EC_500);
        }
        return CI_ERROR;
    }

    return CI_OK;
}


/*
 * メインリクエスト処理
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *   CI_OK      : 正常
 *   CI_ERROR   : 異常
 */
static int do_request(ci_request_t * req)
{
    ci_service_xdata_t *srv_xdata = NULL;
    int res, preview_status = 0, auth_status;
    int ret_status = CI_OK; /*By default ret_status is CI_OK, on error must set to CI_ERROR*/

    /* ICAPリクエストヘッダ解析 */
    res = parse_header(req);
    if (res != EC_100) {
        /*if read some data, bad request or Service not found or Server error or what else,
          else connection timeout, or client closes the connection*/
        req->return_code = res;
        req->keepalive = 0;   // Error occured, close the connection ......
        if (res > EC_100 && req->request_header->bufused > 0)
            ec_responce(req, res);
        ci_debug_printf((req->request_header->bufused ? 5 : 11), "Error %d while parsing headers :(%d)\n",
                        res, req->request_header->bufused);
        return CI_ERROR;
    }
    assert(req->current_service_mod);

    /* サービス拡張オブジェクト取得 */
    srv_xdata = service_data(req->current_service_mod);
    if (!srv_xdata || srv_xdata->status != CI_SERVICE_OK) {
        ci_debug_printf(2, "Service %s not initialized\n", req->current_service_mod->mod_name);
        req->keepalive = 0;
        ec_responce(req, EC_500);
        return CI_ERROR;
    }

    /* 認証処理 */
    if ((auth_status = access_check_request(req)) == CI_ACCESS_DENY) {
        req->keepalive = 0;
        if (req->auth_required) {
            ec_responce(req, EC_407); /*Responce with authentication required */
        } else {
            ec_responce(req, EC_403); /*Forbitten*/
        }
        ci_debug_printf(3, "Request not authenticated, status: %d\n", auth_status);
        return CI_ERROR;      /*Or something that means authentication error */
    }

    /* カプセル化ヘッダ解析 */
    if (res == EC_100) {
        res = parse_encaps_headers(req);
        if (res != EC_100) {
            req->keepalive = 0;
            ec_responce(req, EC_400);
            return CI_ERROR;
        }
    }

    /* サービス固有の初期化処理呼び出し */
    if (req->current_service_mod->mod_init_request_data)
        req->service_data =
            req->current_service_mod->mod_init_request_data(req);
    else
        req->service_data = NULL;

    ci_debug_printf(8, "Requested service: %s\n",
                    req->current_service_mod->mod_name);

    switch (req->type) {
    case ICAP_OPTIONS:
        options_responce(req);
        ret_status = CI_OK;
        break;
    case ICAP_REQMOD:
    case ICAP_RESPMOD:
        if (req->preview >= 0) /*we are inside preview*/
            /* do_request_preview returns CI_OK, CI_EOF or CI_ERROR */
            /* Preview 処理 */
            preview_status = do_request_preview(req);
        else {
            /* do_fake_preview return CI_OK or CI_ERROR. */
            /* 非 Preview 処理 */
            preview_status = do_fake_preview(req);
        }

        if (preview_status == CI_ERROR) {
            ret_status = CI_ERROR;
            break;
        } else if (preview_status == CI_EOF)
            req->return_code = EC_200; /*Equivalent to "100 Continue"*/

        if (req->return_code == EC_204) /*Allow 204,  Stop processing here*/
            break;
        /*else 100 continue or 206  response or Internal error*/
        else if (req->return_code != EC_100 && req->return_code != EC_200 && req->return_code != EC_206) {
            ec_responce(req, EC_500);
            ret_status = CI_ERROR;
            break;
        }

        if (req->return_code == EC_100 && req->hasbody && preview_status != CI_EOF) {
            req->return_code = EC_200; /*We have to repsond with "200 OK"*/
            ci_debug_printf(9, "Going to get/send body data.....\n");
            ret_status = get_send_body(req, 0);
            if (ret_status == CI_ERROR) {
                req->keepalive = 0; /*close the connection*/
                ci_debug_printf(5,
                                "An error occured. Parse error or the client closed the connection (res:%d, preview status:%d)\n",
                                ret_status, preview_status);
                break;
            }
        }

        /*We have received all data from the client. Call the end-of-data service handler and process*/
        /* データ取得完了処理 */
        ret_status = do_end_of_data(req);
        if (ret_status == CI_ERROR) {
            req->keepalive = 0; /*close the connection*/
            break;
        }

        if (req->return_code == EC_204)
            break;  /* Nothing to be done, stop here*/
        /*else we have to send response to the client*/


        unlock_data(req); /*unlock data if locked so that it can be send to the client*/
        /* 残データ送信処理 */
        ret_status = send_remaining_response(req);
        if (ret_status == CI_ERROR) {
            req->keepalive = 0; /*close the connection*/
            ci_debug_printf(5, "Error while sending rest responce or client closed the connection\n");
        }
        /*We are finished here*/
        break;
    default:
        req->keepalive = 0; /*close the connection*/
        ret_status = CI_ERROR;
        break;
    }

    /* サービス固有のリクエスト解放ハンドラ呼び出し */
    if (req->current_service_mod->mod_release_request_data
            && req->service_data)
        req->current_service_mod->mod_release_request_data(req->service_data);

//     debug_print_request(req);
    return ret_status;
}

/*
 * リクエスト処理
 *
 * 引数
 *   ci_request_t  *req : リクエストオブジェクト
 *
 * 復帰値
 *   res
 *   CI_NO_STATUS
 */
int process_request(ci_request_t * req)
{
    int res;
    ci_service_xdata_t *srv_xdata;

    /* メインリクエスト処理 */
    res = do_request(req);

    /* 未処理リクエストデータあり */
    if (req->pstrblock_read_len) {
        ci_debug_printf(5, "There are unparsed data od size %d: \"%.*s\"\n. Move to connection buffer\n", req->pstrblock_read_len, (req->pstrblock_read_len < 64 ? req->pstrblock_read_len : 64), req->pstrblock_read);
    }

    if (res<0 && req->request_header->bufused == 0) /*Did not read anything*/
        return CI_NO_STATUS;

    /* 統計情報更新 */
    if (STATS) {
        /* サービス拡張オブジェクト取得 */
        if (req->return_code != EC_404 && req->current_service_mod)
            srv_xdata = service_data(req->current_service_mod);
        else
            srv_xdata = NULL;

        /*
         * スレッド間での共有資源アクセスの排他ロック取得
         * 排他ロックが取得できるまで待機する
         */
        STATS_LOCK();

        /* 総リクエスト数 */
        if (STAT_REQUESTS >= 0) STATS_INT64_INC(STAT_REQUESTS,1);

        /*  メソッド毎リクエスト数 */
        if (req->type == ICAP_REQMOD) {
            STATS_INT64_INC(STAT_REQMODS, 1);
            if (srv_xdata)
                STATS_INT64_INC(srv_xdata->stat_reqmods, 1);
        } else if (req->type == ICAP_RESPMOD) {
            STATS_INT64_INC(STAT_RESPMODS, 1);
            if (srv_xdata)
                STATS_INT64_INC(srv_xdata->stat_respmods, 1);
        } else if (req->type == ICAP_OPTIONS) {
            STATS_INT64_INC(STAT_OPTIONS, 1);
            if (srv_xdata)
                STATS_INT64_INC(srv_xdata->stat_options, 1);
        }

        if (res <0 && STAT_FAILED_REQUESTS >= 0)
            STATS_INT64_INC(STAT_FAILED_REQUESTS,1);
        else if (req->return_code == EC_204) {
            STATS_INT64_INC(STAT_ALLOW204, 1);
            if (srv_xdata)
                STATS_INT64_INC(srv_xdata->stat_allow204, 1);
        }

        /* 各種送受信サイズ */
        if (STAT_BYTES_IN >= 0) STATS_KBS_INC(STAT_BYTES_IN, req->bytes_in);
        if (STAT_BYTES_OUT >= 0) STATS_KBS_INC(STAT_BYTES_OUT, req->bytes_out);
        if (STAT_HTTP_BYTES_IN >= 0) STATS_KBS_INC(STAT_HTTP_BYTES_IN, req->http_bytes_in);
        if (STAT_HTTP_BYTES_OUT >= 0) STATS_KBS_INC(STAT_HTTP_BYTES_OUT, req->http_bytes_out);
        if (STAT_BODY_BYTES_IN >= 0) STATS_KBS_INC(STAT_BODY_BYTES_IN, req->body_bytes_in);
        if (STAT_BODY_BYTES_OUT >= 0) STATS_KBS_INC(STAT_BODY_BYTES_OUT, req->body_bytes_out);

        if (srv_xdata) {
            if (srv_xdata->stat_bytes_in >= 0)
                STATS_KBS_INC(srv_xdata->stat_bytes_in, req->bytes_in);
            if (srv_xdata->stat_bytes_out >= 0)
                STATS_KBS_INC(srv_xdata->stat_bytes_out, req->bytes_out);
            if (srv_xdata->stat_http_bytes_in >= 0)
                STATS_KBS_INC(srv_xdata->stat_http_bytes_in, req->http_bytes_in);
            if (srv_xdata->stat_http_bytes_out >= 0)
                STATS_KBS_INC(srv_xdata->stat_http_bytes_out, req->http_bytes_out);
            if (srv_xdata->stat_body_bytes_in >= 0)
                STATS_KBS_INC(srv_xdata->stat_body_bytes_in, req->body_bytes_in);
            if (srv_xdata->stat_body_bytes_out >= 0)
                STATS_KBS_INC(srv_xdata->stat_body_bytes_out, req->body_bytes_out);
        }

        /* 排他ロック解除 */
        STATS_UNLOCK();
    }

    return res; /*Allow to log even the failed requests*/
}
