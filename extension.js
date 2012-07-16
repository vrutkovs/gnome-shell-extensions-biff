/*
 * Copyright (C) 2012 Chris Burdess <dog@gnu.org>
 *
 * Gnome Shell Biff is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * Gnome Shell Biff is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with Gnome Documents; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

//const EDataServer = imports.gi.EDataServer;
const Mainloop = imports.mainloop;
const GConf = imports.gi.GConf;
const GLib = imports.gi.GLib;
const Gio = imports.gi.Gio;
const GnomeKeyring = imports.gi.GnomeKeyring;
const Lang = imports.lang;
//const Logger = imports.logger.logger;
const Main = imports.ui.main;
const Utils = imports.misc.util;
const St = imports.gi.St;

const Extension = imports.misc.extensionUtils.getCurrentExtension();
const OAuth = Extension.imports.oauth;

let check_interval, enabled, check_mail_pid;
let button, extension_path, icon_read, icon_unread, label;
let queue;
let queue_counter = 0, checking = false;

function ImapURL(url) {
    this.init(url);
}

ImapURL.prototype = {

init : function(url) {
    this.port = 143;
    let si = url.indexOf(":");
    this.scheme = url.substring(0, si);
    if (url.indexOf("security-method=ssl-on-alternate-port") != -1) {
        this.scheme = "imaps";
    }
    if (this.scheme === "imaps") {
        this.port = 993;
    }
    si += 3;
    let ei = url.indexOf("/", si);
    this.mailbox = url.substring(ei + 1);
    let ui = url.lastIndexOf("@", ei);
    this.host = url.substring(ui + 1, ei);
    let ci = this.host.lastIndexOf(":");
    if (ci != -1) {
        this.port = parseInt(this.host.substring(ci + 1));
        this.host = this.host.substring(0, ci);
    }
    this.username = url.substring(si, ui);
    this.password = null;
    ci = this.username.lastIndexOf(":");
    if (ci != -1) {
        this.password = GLib.uri_unescape_string(this.username.substring(ci + 1), "");
        this.username = this.username.substring(0, ci);
    }
    ci = this.username.indexOf(";auth=");
    if (ci != -1) {
        this.username = this.username.substring(0, ci);
    }
    this.username = GLib.uri_unescape_string(this.username, "");
    ci = this.mailbox.indexOf(";");
    if (ci != -1) {
        this.mailbox = this.mailbox.substring(0, ci);
    }
    this.mailbox = GLib.uri_unescape_string(this.mailbox, "");
    if (this.mailbox.length == 0) {
        this.mailbox = "INBOX";
    }
    this.auth_str = null;
}

};

function open_mua() {
    check_mail();
    try {
        let appinfo = Gio.app_info_get_default_for_type("x-scheme-handler/mailto", false);
        let success = appinfo.launch([], null);
        if (!success) {
            global.log("Error launching default MUA");
        }
    } catch (err) {
        global.log("Can't start default MUA: "+err.message);
    }
}

function check_mail() {
    try {
        if (!checking) {
            checking = true;
            global.log("check mail");
            queue_counter++;
            if (queue_counter > 20) {
                // periodically check for new accounts
                queue = get_mail_accounts();
                queue_counter = 0;
            }
            for (let i = 0; i < queue.length; i++) {
                check_account(queue[i]);
            }
            checking = false;
        }
    } catch (err) {
        global.log("check_mail: "+err.message);
    }
    return true; // continue this timer
}

function done_callback() {
}

function get_mail_accounts() {
    try {
        let ret = new Array();
        let gconfclient = GConf.Client.get_default();
        let list = gconfclient.get("/apps/evolution/mail/accounts").get_list(GConf.VALUE_STRING);
        for (let i = 0; i < list.length; i++) {
            let xml = list[i].get_string();
            // TODO reinstate this when EDataServer's e_account_get_string
            // works
            //let account = EDataServer.Account.new_from_xml(xml);
            //let url = account.get_string(6); // E_ACCOUNT_SOURCE_URL
            let si = xml.indexOf("<url>");
            let ei = xml.indexOf("</url>", si);
            let url = new ImapURL(xml.substring(si + 5, ei));
            if (url.scheme.indexOf("imap") == 0) {
                ret.push(url);
            }
        }
        return ret;
    } catch (err) {
        global.log("Error retrieving mail accounts: "+err.message);
    }
}

function check_account(url) {
    if (url.password == null) {
        url.password = get_password("imap", url.host, url.username);
        if (url.password == null) {
            url.password = get_password("imapx", url.host, url.username);
        }
    }
    if (url.password == null) {
        // TODO ask for password if none found and store it
        try {
            const Goa = imports.gi.Goa;
            let aClient = Goa.Client.new_sync (null);
            let accounts = aClient.get_accounts();
            for (let index in accounts) {
                let account = accounts[index]
                imap_user_name = account.get_mail().imap_user_name;
                if (imap_user_name != url.username)
                    return;
                service = "https://mail.google.com/mail/b/"+imap_user_name+"/imap/"
                let oAuth = new OAuth.OAuth(account,service);
                url.auth_str = oAuth.oAuth_str;
            }
        } catch (err) {
            global.log("Can't retrieve password for "+url.username+" on "+url.host);
            return;
        }
    }
    global.log("checking "+url.host);
    new IMAPConnection(url.host, url.port, url.username, url.password, url.auth_str, (url.scheme === "imaps"), url.mailbox, update_unread_count, done_callback).connect();
}

function get_password(scheme, host, username) {
    let password = null;
    try {
        let type = 1; /* GNOME_KEYRING_ITEM_NETWORK_PASSWORD */
        let attributes = GnomeKeyring.attribute_list_new();
        GnomeKeyring.attribute_list_append_string(attributes, "protocol", scheme);
        GnomeKeyring.attribute_list_append_string(attributes, "server", host);
        GnomeKeyring.attribute_list_append_string(attributes, "user", username);
        let [result, found] = GnomeKeyring.find_items_sync(type, attributes);
        if (result == 0 /* GNOME_KEYRING_RESULT_OK */) {
            let f = found[0];
            password = f.secret;
        }
    } catch (err) {
        global.log("get_password: "+err.message);
    }
    return password;
}

function update_unread_count(account, value) {
    global.log(account+": "+value+" new messages");
    if (value != null) {
        try {
            let total = value;
            let gconfclient = GConf.Client.get_default();
            // GConfClient.set_list doesn't work, use string instead
            let countsval = gconfclient.get("/apps/gnome-biff/counts-string");
            let counts = null;
            let acc = account + "=" + value;
            if (countsval != null) {
                counts = countsval.get_string();
            }
            if (counts == null) {
                counts = "";
            }
            let tokens = counts.split(",");
            for (let i = 0; i < tokens.length; i++) {
                let line = tokens[i].trim();
                if (line.length > 0) {
                    let ei = line.lastIndexOf("=");
                    let head = line.substring(0, ei);
                    let tail = line.substring(ei + 1);
                    if (head === account) {
                    } else {
                        total = total + parseInt(tail);
                        acc = acc + "," + line;
                    }
                }
            }
            gconfclient.set_string("/apps/gnome-biff/counts-string", acc);
            set_message_count(total);
        } catch (err) {
            global.log("Error updating new message count list: "+err.message);
        }
    }
}

function init(meta) {
    extension_path = meta.path;
    _init();
}

function enable() {
    enabled = true;
    try {
        Main.panel._rightBox.insert_child_at_index(button, 0); // gnome 3.4
    } catch (err) {
        Main.panel._rightBox.insert_actor(button, 0);
    }
    check_interval = 30;
    let gconfclient = GConf.Client.get_default();
    let cci = gconfclient.get("/apps/gnome-biff/check-interval");
    if (cci != null) {
        check_interval = cci.get_int();
        if (check_interval < 10) {
            check_interval = 10; // don't invoke check_mail too frequently
        }
    }
    queue = get_mail_accounts();
    check_mail_pid = GLib.timeout_add_seconds(0, check_interval, check_mail);
    check_mail();
}

function disable() {
    enabled = false;
    Main.panel._rightBox.remove_actor(button);
    if (check_mail_pid != null) {
        Mainloop.source_remove(check_mail_pid);
        check_mail_pid = null;
    }
}

// TODO move this to a separate prototype

function _init() {
    button = new St.Bin({ style_class: 'panel-button', reactive: true, can_focus: true, x_fill:true, y_fill: false, track_hover:true });
    icon_read = new St.Icon({ icon_name: 'mail-read-symbolic', icon_size: 16, icon_type: St.IconType.SYMBOLIC, style_class: 'system_status_icon' });
    icon_unread = new St.Icon({ icon_name: 'mail-unread-symbolic', icon_size: 16, icon_type: St.IconType.SYMBOLIC, style_class: 'system_status_icon' });
    icon_unread.hide();
    label = new St.Label({ style_class: 'button_text', text: '...' });
    let box = new St.BoxLayout();
    try {
        box.insert_child_at_index(this.icon_read, 1);
        box.insert_child_at_index(this.icon_unread, 1);
        box.insert_child_at_index(this.label, 2);
    } catch (err) {
        box.insert_actor(this.icon_read, 1);
        box.insert_actor(this.icon_unread, 1);
        box.insert_actor(this.label, 2);
    }
    button.set_child(box);
    button.connect('button-press-event', open_mua);
}

function set_message_count(count) {
    if (count > 0) {
        label.text = count.toString();
        icon_read.hide();
        icon_unread.show();
        label.show();
    } else {
        icon_unread.hide();
        icon_read.show();
        label.hide();
    }
}

/* imap */

function IMAPConnection(host, port, username, password, auth_str, ssl, mailbox, recent_callback, done_callback) {
    this.init(host, port, username, password, auth_str, ssl, mailbox, recent_callback, done_callback);
}

IMAPConnection.prototype = {

init : function(host, port, username, password, auth_str, ssl, mailbox, recent_callback, done_callback) {
    this.IMAP_AUTH_METHODS = new Array("CRAM-MD5", "PLAIN", "XOAUTH");
    this.host = host;
    this.port = port;
    this.username = username;
    this.id = username+"@"+host+":"+port;
    this.password = password;
    this.auth_str = auth_str;
    this.ssl = ssl;
    this.try_starttls = !ssl;
    this.can_starttls = false;
    if (mailbox == "") {
        mailbox = "INBOX";
    }
    this.mailbox = mailbox;
    this.recent_callback = recent_callback;
    this.done_callback = done_callback;
    this.tag = 0;
    this.auth_capabilities = [];
    this.sasl_client = null;
    this.sasl_ir = false;
    this.resolver = Gio.Resolver.get_default();
    this.conn = null;
},

error : function() {
    this.done_callback.apply(this, []);
},

connect : function() {
    global.log(this.host+": connect");
    this.resolver.lookup_by_name_async(this.host, null, Lang.bind(this, function(resolver0, result0, data0) {
        global.log(this.host+": resolver_callback");
        try {
            let addresses = this.resolver.lookup_by_name_finish(result0);
            if (typeof(addresses) != "undefined" && addresses.length > 0) {
                //let ia = Gio.InetAddress.new_from_string(addresses[0].to_string());
                let ia = addresses[0];
                let isa = Gio.InetSocketAddress.new(ia, this.port);
                let socket = new Gio.SocketClient();
                if (this.ssl) {
                    socket.set_tls(true);
                    socket.set_tls_validation_flags(0);
                }
                socket.connect_async(isa, null, Lang.bind(this, function(socket1, result1, data1) {
                    global.log(this.host+": connect_callback");
                    try {
                        this.conn = socket1.connect_finish(result1);
                        if (this.conn != null) {
                            this.connected();
                        } else {
                            global.log("Cannot connect to "+this.host);
                            this.error();
                        }
                    } catch (err) {
                        global.log("Error connecting to "+this.host+": "+err.message);
                        this.error();
                    }
                }), null);
            } else {
                global.log("Cannot resolve "+this.host);
                this.error();
            }
        } catch (err) {
            global.log("Error resolving "+this.host+": "+err.message);
            this.error();
        }
    }), null);
},

connected : function() {
    global.log(this.host+": connected");
    this.is = Gio.DataInputStream.new(this.conn.get_input_stream());
    this.os = Gio.DataOutputStream.new(this.conn.get_output_stream());
    this.is.set_buffer_size(32768);
    this.readline(this.welcome_callback);
},

new_tag : function() {
    this.tag++;
    return "A" + this.tag;
},

readline : function(callback) {
    if (this.conn.is_closed()) {
        global.log(this.host+": stream is closed");
        this.error();
        return;
    }
    this.is.read_line_async(0, null, Lang.bind(this, function (stream, result) {
        let buf = this.is.read_line_finish(result);
        let line = new String(buf[0]).substr(0, buf[0].length - 1);
        global.log(this.host+" < "+line);
        callback.apply(this, [line]);
    }));
},

writeline : function(line) {
    if (this.conn.is_closed()) {
        global.log(this.host+": stream is closed");
        this.error();
        return;
    }
    global.log(this.host+" > "+line);
    this.os.put_string(line, null);
},

welcome_callback : function(line) {
    global.log(this.host+": welcome_callback: "+line);
    var tokens = this.tokenize(line);
    if (tokens[0] === "*" && tokens[1] === "OK") {
        if (this.is_list(tokens[2])) {
            if (this.handle_capability_list(this.tokenize_list(tokens[2]))) {
                this.starttls();
                return;
            }
        } 
        this.capability();
        return;
    }
    global.log("Unexpected IMAP response from "+this.host+": "+line);
    this.close();
},

capability : function() {
    global.log(this.host+": capability");
    this.writeline(this.new_tag()+" CAPABILITY\r\n");
    this.readline(this.capability_callback);
},

capability_callback : function(line) {
    global.log(this.host+": capability_callback: "+line);
    var tokens = this.tokenize(line);
    if (tokens[0] === "*") {
        tokens.shift();
        this.handle_capability_list(tokens);
        this.readline(this.capability_callback);
    } else if (tokens[1] === "OK") {
        this.starttls();
    } else {
        global.log("Unexpected SELECT response from "+this.host+": "+line);
        this.close();
    }
},

handle_capability_list : function(list) {
    global.log(this.host+": capability="+list+" try_starttls="+this.try_starttls);
    if (list[0] === "CAPABILITY") {
        for (var i = 1; i < list.length; i++) {
            if (list[i] === "STARTTLS" && this.try_starttls) {
                this.can_starttls = true;
            } else if (list[i] === "SASL-IR") {
                this.sasl_ir = true;
            } else if (list[i].substr(0, 5) === "AUTH=") {
                this.auth_capabilities.push(list[i].substr(5));
            }
        }
        return true;
    }
    return false;;
},

starttls : function() {
    global.log(this.host+": starttls");
    if (this.try_starttls && this.can_starttls) {
        this.writeline(this.new_tag()+" STARTTLS\r\n");
        this.readline(this.starttls_callback);
    } else {
        this.authenticate();
    }
},

starttls_callback : function(line) {
    global.log(this.host+": starttls_callback: "+line);
    var tokens = this.tokenize(line);
    if (tokens[1] === "OK") {
        var addr = Gio.InetAddress.new_any(2); // IPv4
        var iaddr = Gio.InetSocketAddress.new(addr, this.port);
        try {
            var sconn = Gio.tls_client_connection_new(this.conn, iaddr);
            sconn.set_validation_flags(0);
            sconn.handshake(null);
            this.is = Gio.DataInputStream.new(sconn.get_input_stream());
            this.os = Gio.DataOutputStream.new(sconn.get_output_stream());
            this.is.set_buffer_size(32768);
            this.try_starttls = false;
        } catch (err) {
            global.log("Error starting TLS on "+this.host+": "+err.message);
        }
        this.authenticate();
    } else {
        global.log("Host "+this.host+" advertised STARTTLS but failed to acknowledge: "+line);
        this.close();
    }
},

authenticate : function() {
    global.log(this.host+": authenticate");
    for (var i = 0; this.sasl_client == null && i < this.IMAP_AUTH_METHODS.length; i++) {
        var method = this.IMAP_AUTH_METHODS[i];
        if (this.auth_capabilities.indexOf(method) != -1) {
            if (method === "CRAM-MD5") {
                this.sasl_client = new CramMD5(this.username, this.password);
            } else if (method == "PLAIN") {
                this.sasl_client = new Plain(this.username, this.password);
            }
        }
    }
    if (this.try_starttls && (this.sasl_client == null || this.sasl_client.is_plaintext())) {
        // this is over an unencrypted connection,
        // we should be using a secure authentication method at least
        global.log("No secure authentication method for "+this.username+" on "+this.host);
        this.logout();
        return;
    }
    if (this.auth_str != null) {
        let cmd = this.new_tag()+" AUTHENTICATE XOAUTH " + this.auth_str;
        this.writeline(cmd+"\r\n");
    } else {
        if (this.sasl_client != null) {
            // fall back to AUTHENTICATE
            global.log("Authenticating to "+this.host+" using "+this.sasl_client.get_name());
            let cmd = this.new_tag()+" AUTHENTICATE "+this.sasl_client.get_name();
            if (this.sasl_client.has_initial_response() && this.sasl_ir) {
                try {
                    let response = this.sasl_client.evaluate_challenge(null);
                    cmd = cmd + " " + response;
                } catch (err) {
                    global.log(this.host+": "+this.sasl_client.get_name()+": "+err.message);
                }
            }
            this.writeline(cmd+"\r\n");
        } else {
            // fall back to LOGIN
            global.log("Login to "+this.host);
            let cmd = this.new_tag()+" LOGIN "+this.quote(this.username)+" "+this.quote(this.password);
            this.writeline(cmd+"\r\n");
        }
    } 
    this.readline(this.auth_callback);
},

auth_callback : function(line) {
    global.log(this.host+": auth_callback: "+line);
    var tokens = this.tokenize(line);
    if (tokens[0] === "+") {
        let response = "";
        if (this.sasl_client != null) {
            try {
                let challenge = line.substring(2).trim();
                response = this.sasl_client.evaluate_challenge(challenge);
            } catch (err) {
                global.log(this.host+": "+this.sasl_client.get_name()+": "+err.message);
            }
        }
        this.writeline(response + "\r\n");
        this.readline(this.auth_callback);
    } else if (tokens[0] === "*") {
        this.readline(this.auth_callback);
    } else if (tokens[1] === "OK") {
        this.stat();
    } else {
        global.log("Authentication failed for "+this.username+" on "+this.host);
        this.close();
    }
},

stat : function() {
    global.log(this.host+": stat");
    let cmd = this.new_tag()+" STATUS "+this.mailbox+" (unseen)";
    this.writeline(cmd+"\r\n");
    this.readline(this.stat_callback);
},

stat_callback : function(line) {
    //global.log(this.host+": stat_callback: "+line);
    var tokens = this.tokenize(line);
    if (tokens[0] === "*") {
        if (tokens[1] === "STATUS") {
            line = new String(line);
            line = line.toLowerCase();
            var lp = line.lastIndexOf(")");
            var sp = line.lastIndexOf("(unseen ", lp);
            if (sp > 0 && lp > sp) {
                var unseen = line.substring(sp + 8, lp);
                this.recent_callback.apply(this, [this.id, parseInt(unseen)]);
            }
        }
        this.readline(this.stat_callback);
    } else if (tokens[1] === "OK") {
        this.logout();
    } else {
        global.log("Unexpected STATUS response from "+this.host+": "+line);
        this.close();
    }
},

logout: function() {
    global.log(this.host+": logout");
    this.writeline(this.new_tag()+" LOGOUT\r\n");
    this.readline(this.logout_callback);
},

logout_callback: function(line) {
    global.log(this.host+": logout_callback");
    var tokens = this.tokenize(line);
    if (tokens[0] === "*") {
        this.readline(this.logout_callback);
    } else if (tokens[1] === "OK") {
        this.close();
    } else {
        global.log("Unexpected LOGOUT response from "+this.host+": "+line);
        this.close();
    }
},

close : function() {
    global.log(this.host+": close");
    try {
        this.conn.close_async(0, null, Lang.bind(this, function(source, result, data) {
            global.log(this.host+": close_callback");
            try {
                this.conn.close_finish(result);
                //this.conn.get_socket().close();
                this.done_callback.apply(this, []);
            } catch (err) {
                global.log("Error closing connection to "+this.host+": "+err.message);
                this.error();
            }
        }), null);
    } catch (err) {
        global.log("Error closing connection to "+this.host+": "+err.message);
        //this.conn.get_socket().close();
        this.error();
    }
},

quote : function(text) {
    if (text.length == 0 || text.indexOf(" ") != -1 || text.indexOf("%") != -1) {
        return "\"" + text + "\"";
    }
    return text;
},

tokenize : function(line) {
    line = new String(line);
    var tokens = new Array();
    var start = 0;
    var end;
    var last = ' ';
    var depth = 0;
    for (end = start; end < line.length; end++) {
        var c = line.charAt(end);
        if (c === '\r' || c === '\n') {
            break;
        }
        if (c === '[') {
            depth++;
        } else if (c === ']') {
            depth--;
        } else if (c === ' ' && depth == 0) {
            if (last != ' ') {
                tokens.push(line.substring(start, end));
            }
            start = end + 1;
        }
        last = c;
    }
    if (end > start) {
        tokens.push(line.substring(start, end));
    }
    return tokens;
},

is_list : function(token) {
    return token.charAt(0) === '[' && token.charAt(token.length - 1) === ']';
},

tokenize_list : function(token) {
    return this.tokenize(token.substring(1, token.length - 1));
}

};

/* sasl */

function CramMD5(username, password) {
    this.init(username, password);
}

CramMD5.prototype = {

init : function(username, password) {
    this.username = username;
    this.password = password;
    this.complete = false;
},

get_name : function() {
    return "CRAM-MD5";
},

is_plaintext : function() {
    return false;
},

has_initial_response : function() {
    return false;
},

evaluate_challenge : function(challenge) {
    let dchallenge = base64_decode(challenge);
    let digest = hex_hmac_md5(this.password, dchallenge);
    let response = this.username + " " + digest;
    let encoded = base64_encode(response);
    this.complete = true;
    return encoded;
},

is_complete : function() {
    return this.complete;
}

/*hmac_md5 : function(key, text) {
    let k_ipad = [];
    let k_opad = [];
    let B = 64;
    if (key.length > B) {
        key = sasl_array_md5(key);
    }
    for (let i = 0; i < B; i++) {
        let val = 0;
        if (i < key.length) {
            val = key[i];
        }
        k_ipad[i] = (val ^ 0x36) & 0xff;
        k_opad[i] = (val ^ 0x5c) & 0xff;
    }
    let digest = sasl_array_md5(k_ipad.concat(text));
    digest = sasl_array_md5(k_opad.concat(digest));
    return digest;
}*/

};

function Plain(username, password) {
    this.init(username, password);
}

Plain.prototype = {

init : function(username, password) {
    this.username = username;
    this.password = password;
    this.complete = false;
},

get_name : function() {
    return "PLAIN";
},

is_plaintext : function() {
    return true;
},

has_initial_response : function() {
    return true;
},

evaluate_challenge : function(challenge) {
    let response = this.username + "\0" + this.username + "\0" + this.password;
    let encoded = base64_encode(response);
    this.complete = true;
    return encoded;
},

is_complete : function() {
    return this.complete;
}

};

/*function sasl_string_to_array(string) {
    let ret = [];
    for (let i = 0; i < string.length; i++) {
        let c = string.charCodeAt(i);
        ret.push(c); // this should probably handle non-ASCII values better
    }
    return ret;
}

function sasl_array_md5(array) {
    let r0 = sasl_array_to_rstr(array);
    let r1 = rstr_md5(r0);
    let r2 = sasl_rstr_to_array(r1);
    return r2;
}

function sasl_array_to_rstr(array) {
    let ret = "";
    for (let i = 0; i < array.length; i++) {
        ret += String.fromCharCode(array[i]);
    }
    return ret;
}

function sasl_rstr_to_array(rstr) {
    let ret = [];
    for (var i = 0; i < rstr.length; i++) {
        ret.push(rstr.charCodeAt(i));
    }
    return ret;
}

function sasl_hex(array) {
    let hex = new Array(0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66);
    let ret = []
    for (let i = 0; i < array.length; i++) {
        let c = array[i] & 0xff;
        ret.push(hex[(c >>> 4) & 0xf]);
        ret.push(hex[c & 0xf]);
    }
    return ret;
}*/

/* base64 */

let src = new Array(
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
    0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
    0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x61, 0x62, 0x63, 0x64,
    0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
    0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x2b, 0x2f
);

let dst = [];
for (let i = 0; i < 0xff; i++) {
    dst[i] = -1;
}
for (let i = 0; i < src.length; i++) {
    dst[src[i]] = i;
}

function base64_encode(sb) {
    let target = [];
    let tlen = ((sb.length + 2 - ((sb.length + 2) % 3)) * 4) / 3;
    for (let si = 0; si < sb.length; si += 3) {
        let blen = sb.length - si;
        let i = 0;
        if (blen == 1) {
            let b1 = sb.charCodeAt(si);
            target.push(src[b1 >>> 2 & 0x3f]);
            target.push(src[(b1 << 4 & 0x30) + (i >>> 4 & 0xf)]);
        } else if (blen == 2) {
            let b1 = sb.charCodeAt(si), b2 = sb.charCodeAt(si + 1);
            target.push(src[b1 >>> 2 & 0x3f]);
            target.push(src[(b1 << 4 & 0x30) + (b2 >>> 4 & 0xf)]);
            target.push(src[(b2 << 2 & 0x3c) + (i >>> 6 & 0x3)]);
        } else {
            let b1 = sb.charCodeAt(si), b2 = sb.charCodeAt(si + 1), b3 = sb.charCodeAt(si + 2);
            target.push(src[b1 >>> 2 & 0x3f]);
            target.push(src[(b1 << 4 & 0x30) + (b2 >>> 4 & 0xf)]);
            target.push(src[(b2 << 2 & 0x3c) + (b3 >>> 6 & 0x3)]);
            target.push(src[b3 & 0x3f]);
        }
    }
    while (target.length < tlen) {
        target.push(0x3d);
    }
    let string = "";
    for (let i = 0; i < target.length; i++) {
        string += String.fromCharCode(target[i]);
    }
    return string;
}

function base64_decode(string) {
    let padding = 0;
    while (string.length - padding > 0 && string[string.length - padding - 1] === "=") {
        padding++;
    }
    let slen = string.length - padding;
    let array = [];
    let si = 0, len = slen;
    while (len > 0) {
        let b0 = dst[string.charCodeAt(si++) & 0xff];
        let b2 = dst[string.charCodeAt(si++) & 0xff];
        array.push(b0 << 2 & 0xfc | b2 >>> 4 & 0x3);
        if (len > 2) {
            b0 = b2;
            b2 = dst[string.charCodeAt(si++) & 0xff];
            array.push(b0 << 4 & 0xf0 | b2 >>> 2 & 0xf);
            if (len > 3) {
                b0 = b2;
                b2 = dst[string.charCodeAt(si++) & 0xff];
                array.push(b0 << 6 & 0xc0 | b2 & 0x3f);
            }
        }
        len = slen - si;
    }
    let ret = "";
    for (let i = 0; i < array.length; i++) {
        ret += String.fromCharCode(array[i]);
    }
    return ret;
}

/* md5 */

/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;   /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = "";  /* base-64 pad character. "=" for strict RFC compliance   */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_md5(s)    { return rstr2hex(rstr_md5(str2rstr_utf8(s))); }
function b64_md5(s)    { return rstr2b64(rstr_md5(str2rstr_utf8(s))); }
function any_md5(s, e) { return rstr2any(rstr_md5(str2rstr_utf8(s)), e); }
function hex_hmac_md5(k, d)
  { return rstr2hex(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d))); }
function b64_hmac_md5(k, d)
  { return rstr2b64(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d))); }
function any_hmac_md5(k, d, e)
  { return rstr2any(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d)), e); }

/*
 * Perform a simple self-test to see if the VM is working
 */
function md5_vm_test()
{
  return hex_md5("abc").toLowerCase() == "900150983cd24fb0d6963f7d28e17f72";
}

/*
 * Calculate the MD5 of a raw string
 */
function rstr_md5(s)
{
  return binl2rstr(binl_md5(rstr2binl(s), s.length * 8));
}

/*
 * Calculate the HMAC-MD5, of a key and some data (raw strings)
 */
function rstr_hmac_md5(key, data)
{
  var bkey = rstr2binl(key);
  if(bkey.length > 16) bkey = binl_md5(bkey, key.length * 8);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = binl_md5(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
  return binl2rstr(binl_md5(opad.concat(hash), 512 + 128));
}

/*
 * Convert a raw string to a hex string
 */
function rstr2hex(input)
{
  try { hexcase } catch(e) { hexcase=0; }
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var output = "";
  var x;
  for(var i = 0; i < input.length; i++)
  {
    x = input.charCodeAt(i);
    output += hex_tab.charAt((x >>> 4) & 0x0F)
           +  hex_tab.charAt( x        & 0x0F);
  }
  return output;
}

/*
 * Convert a raw string to a base-64 string
 */
function rstr2b64(input)
{
  try { b64pad } catch(e) { b64pad=''; }
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var output = "";
  var len = input.length;
  for(var i = 0; i < len; i += 3)
  {
    var triplet = (input.charCodeAt(i) << 16)
                | (i + 1 < len ? input.charCodeAt(i+1) << 8 : 0)
                | (i + 2 < len ? input.charCodeAt(i+2)      : 0);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > input.length * 8) output += b64pad;
      else output += tab.charAt((triplet >>> 6*(3-j)) & 0x3F);
    }
  }
  return output;
}

/*
 * Convert a raw string to an arbitrary string encoding
 */
function rstr2any(input, encoding)
{
  var divisor = encoding.length;
  var i, j, q, x, quotient;

  /* Convert to an array of 16-bit big-endian values, forming the dividend */
  var dividend = Array(Math.ceil(input.length / 2));
  for(i = 0; i < dividend.length; i++)
  {
    dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
  }

  /*
   * Repeatedly perform a long division. The binary array forms the dividend,
   * the length of the encoding is the divisor. Once computed, the quotient
   * forms the dividend for the next step. All remainders are stored for later
   * use.
   */
  var full_length = Math.ceil(input.length * 8 /
                                    (Math.log(encoding.length) / Math.log(2)));
  var remainders = Array(full_length);
  for(j = 0; j < full_length; j++)
  {
    quotient = Array();
    x = 0;
    for(i = 0; i < dividend.length; i++)
    {
      x = (x << 16) + dividend[i];
      q = Math.floor(x / divisor);
      x -= q * divisor;
      if(quotient.length > 0 || q > 0)
        quotient[quotient.length] = q;
    }
    remainders[j] = x;
    dividend = quotient;
  }

  /* Convert the remainders to the output string */
  var output = "";
  for(i = remainders.length - 1; i >= 0; i--)
    output += encoding.charAt(remainders[i]);

  return output;
}

/*
 * Encode a string as utf-8.
 * For efficiency, this assumes the input is valid utf-16.
 */
function str2rstr_utf8(input)
{
  var output = "";
  var i = -1;
  var x, y;

  while(++i < input.length)
  {
    /* Decode utf-16 surrogate pairs */
    x = input.charCodeAt(i);
    y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    if(0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF)
    {
      x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
      i++;
    }

    /* Encode output as utf-8 */
    if(x <= 0x7F)
      output += String.fromCharCode(x);
    else if(x <= 0x7FF)
      output += String.fromCharCode(0xC0 | ((x >>> 6 ) & 0x1F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0xFFFF)
      output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0x1FFFFF)
      output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                                    0x80 | ((x >>> 12) & 0x3F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
  }
  return output;
}

/*
 * Encode a string as utf-16
 */
function str2rstr_utf16le(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode( input.charCodeAt(i)        & 0xFF,
                                  (input.charCodeAt(i) >>> 8) & 0xFF);
  return output;
}

function str2rstr_utf16be(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF,
                                   input.charCodeAt(i)        & 0xFF);
  return output;
}

/*
 * Convert a raw string to an array of little-endian words
 * Characters >255 have their high-byte silently ignored.
 */
function rstr2binl(input)
{
  var output = Array(input.length >> 2);
  for(var i = 0; i < output.length; i++)
    output[i] = 0;
  for(var i = 0; i < input.length * 8; i += 8)
    output[i>>5] |= (input.charCodeAt(i / 8) & 0xFF) << (i%32);
  return output;
}

/*
 * Convert an array of little-endian words to a string
 */
function binl2rstr(input)
{
  var output = "";
  for(var i = 0; i < input.length * 32; i += 8)
    output += String.fromCharCode((input[i>>5] >>> (i % 32)) & 0xFF);
  return output;
}

/*
 * Calculate the MD5 of an array of little-endian words, and a bit length.
 */
function binl_md5(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << ((len) % 32);
  x[(((len + 64) >>> 9) << 4) + 14] = len;

  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;

    a = md5_ff(a, b, c, d, x[i+ 0], 7 , -680876936);
    d = md5_ff(d, a, b, c, x[i+ 1], 12, -389564586);
    c = md5_ff(c, d, a, b, x[i+ 2], 17,  606105819);
    b = md5_ff(b, c, d, a, x[i+ 3], 22, -1044525330);
    a = md5_ff(a, b, c, d, x[i+ 4], 7 , -176418897);
    d = md5_ff(d, a, b, c, x[i+ 5], 12,  1200080426);
    c = md5_ff(c, d, a, b, x[i+ 6], 17, -1473231341);
    b = md5_ff(b, c, d, a, x[i+ 7], 22, -45705983);
    a = md5_ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
    d = md5_ff(d, a, b, c, x[i+ 9], 12, -1958414417);
    c = md5_ff(c, d, a, b, x[i+10], 17, -42063);
    b = md5_ff(b, c, d, a, x[i+11], 22, -1990404162);
    a = md5_ff(a, b, c, d, x[i+12], 7 ,  1804603682);
    d = md5_ff(d, a, b, c, x[i+13], 12, -40341101);
    c = md5_ff(c, d, a, b, x[i+14], 17, -1502002290);
    b = md5_ff(b, c, d, a, x[i+15], 22,  1236535329);

    a = md5_gg(a, b, c, d, x[i+ 1], 5 , -165796510);
    d = md5_gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
    c = md5_gg(c, d, a, b, x[i+11], 14,  643717713);
    b = md5_gg(b, c, d, a, x[i+ 0], 20, -373897302);
    a = md5_gg(a, b, c, d, x[i+ 5], 5 , -701558691);
    d = md5_gg(d, a, b, c, x[i+10], 9 ,  38016083);
    c = md5_gg(c, d, a, b, x[i+15], 14, -660478335);
    b = md5_gg(b, c, d, a, x[i+ 4], 20, -405537848);
    a = md5_gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
    d = md5_gg(d, a, b, c, x[i+14], 9 , -1019803690);
    c = md5_gg(c, d, a, b, x[i+ 3], 14, -187363961);
    b = md5_gg(b, c, d, a, x[i+ 8], 20,  1163531501);
    a = md5_gg(a, b, c, d, x[i+13], 5 , -1444681467);
    d = md5_gg(d, a, b, c, x[i+ 2], 9 , -51403784);
    c = md5_gg(c, d, a, b, x[i+ 7], 14,  1735328473);
    b = md5_gg(b, c, d, a, x[i+12], 20, -1926607734);

    a = md5_hh(a, b, c, d, x[i+ 5], 4 , -378558);
    d = md5_hh(d, a, b, c, x[i+ 8], 11, -2022574463);
    c = md5_hh(c, d, a, b, x[i+11], 16,  1839030562);
    b = md5_hh(b, c, d, a, x[i+14], 23, -35309556);
    a = md5_hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
    d = md5_hh(d, a, b, c, x[i+ 4], 11,  1272893353);
    c = md5_hh(c, d, a, b, x[i+ 7], 16, -155497632);
    b = md5_hh(b, c, d, a, x[i+10], 23, -1094730640);
    a = md5_hh(a, b, c, d, x[i+13], 4 ,  681279174);
    d = md5_hh(d, a, b, c, x[i+ 0], 11, -358537222);
    c = md5_hh(c, d, a, b, x[i+ 3], 16, -722521979);
    b = md5_hh(b, c, d, a, x[i+ 6], 23,  76029189);
    a = md5_hh(a, b, c, d, x[i+ 9], 4 , -640364487);
    d = md5_hh(d, a, b, c, x[i+12], 11, -421815835);
    c = md5_hh(c, d, a, b, x[i+15], 16,  530742520);
    b = md5_hh(b, c, d, a, x[i+ 2], 23, -995338651);

    a = md5_ii(a, b, c, d, x[i+ 0], 6 , -198630844);
    d = md5_ii(d, a, b, c, x[i+ 7], 10,  1126891415);
    c = md5_ii(c, d, a, b, x[i+14], 15, -1416354905);
    b = md5_ii(b, c, d, a, x[i+ 5], 21, -57434055);
    a = md5_ii(a, b, c, d, x[i+12], 6 ,  1700485571);
    d = md5_ii(d, a, b, c, x[i+ 3], 10, -1894986606);
    c = md5_ii(c, d, a, b, x[i+10], 15, -1051523);
    b = md5_ii(b, c, d, a, x[i+ 1], 21, -2054922799);
    a = md5_ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
    d = md5_ii(d, a, b, c, x[i+15], 10, -30611744);
    c = md5_ii(c, d, a, b, x[i+ 6], 15, -1560198380);
    b = md5_ii(b, c, d, a, x[i+13], 21,  1309151649);
    a = md5_ii(a, b, c, d, x[i+ 4], 6 , -145523070);
    d = md5_ii(d, a, b, c, x[i+11], 10, -1120210379);
    c = md5_ii(c, d, a, b, x[i+ 2], 15,  718787259);
    b = md5_ii(b, c, d, a, x[i+ 9], 21, -343485551);

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
  }
  return Array(a, b, c, d);
}

/*
 * These functions implement the four basic operations the algorithm uses.
 */
function md5_cmn(q, a, b, x, s, t)
{
  return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s),b);
}
function md5_ff(a, b, c, d, x, s, t)
{
  return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
}
function md5_gg(a, b, c, d, x, s, t)
{
  return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
}
function md5_hh(a, b, c, d, x, s, t)
{
  return md5_cmn(b ^ c ^ d, a, b, x, s, t);
}
function md5_ii(a, b, c, d, x, s, t)
{
  return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function bit_rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}
