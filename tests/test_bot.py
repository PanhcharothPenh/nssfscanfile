import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import bot


def make_update(text=None, chat_type="private", caption=None, user_id=1):
    msg = MagicMock()
    msg.text, msg.caption = text, caption
    msg.entities, msg.caption_entities = [], []
    msg.chat_id, msg.chat = 5, SimpleNamespace(type=chat_type)
    msg.from_user = SimpleNamespace(id=user_id, first_name="A", last_name="", username="a")
    msg.reply_text = AsyncMock()
    return SimpleNamespace(message=msg, effective_user=msg.from_user, effective_chat=msg.chat), msg


def run_handler(update):
    bot.rate_limiter = bot.UserRateLimiter(100)
    asyncio.run(bot.handle_message(update, MagicMock()))


def test_build_application_registers_handlers(monkeypatch):
    monkeypatch.setattr(bot, "TELEGRAM_BOT_TOKEN", "123456:TEST-TOKEN")
    app = bot.build_application(with_post_init=False)
    assert app is not None


def test_private_chat_always_replies(monkeypatch):
    logged = []
    monkeypatch.setattr(bot, "alog_scan_event", AsyncMock(side_effect=lambda **k: logged.append(k)))
    upd, msg = make_update("hello friend")
    run_handler(upd)
    msg.reply_text.assert_awaited_once()
    assert logged[0]["risk_level"] == "SAFE"


def test_group_stays_silent_for_safe_but_warns_for_scam(monkeypatch):
    monkeypatch.setattr(bot, "alog_scan_event", AsyncMock())
    upd, msg = make_update("lunch at noon?", chat_type="supergroup")
    run_handler(upd)
    msg.reply_text.assert_not_awaited()

    upd, msg = make_update("URGENT ABA account suspended, send OTP https://aba-verify.xyz", chat_type="supergroup")
    run_handler(upd)
    msg.reply_text.assert_awaited_once()
    assert "parse_mode" in msg.reply_text.await_args.kwargs


def test_scan_command_without_args_shows_usage(monkeypatch):
    monkeypatch.setattr(bot, "alog_scan_event", AsyncMock())
    upd, msg = make_update("/scan")
    run_handler(upd)
    assert "/scan" in msg.reply_text.await_args.args[0]


def test_large_file_is_reported_as_not_scanned(monkeypatch):
    monkeypatch.setattr(bot, "alog_scan_event", AsyncMock())
    upd, msg = make_update()
    msg.document = SimpleNamespace(file_name="big.apk", file_size=60_000_000, file_id="f")
    progress = MagicMock(edit_text=AsyncMock())
    msg.reply_text = AsyncMock(return_value=progress)
    bot.rate_limiter = bot.UserRateLimiter(100)
    asyncio.run(bot.handle_document(upd, MagicMock()))
    text = progress.edit_text.await_args.args[0]
    assert "មិនទាន់ត្រូវបានស្កេន" in text and "🟢" not in text


def test_pasted_hash_triggers_lookup(monkeypatch):
    monkeypatch.setattr(bot, "alog_scan_event", AsyncMock())
    seen = []

    async def fake_lookup(digest):
        seen.append(digest)
        return {"status": "DANGEROUS", "scanned": True, "filename": "evil.rar", "malicious_count": 9,
                "suspicious_count": 0, "total_engines": 70}

    monkeypatch.setattr(bot.vt_scanner, "lookup_hash", fake_lookup)
    upd, msg = make_update("a" * 64)
    run_handler(upd)
    assert seen == ["a" * 64]
    assert "🔴" in msg.reply_text.await_args.args[0]


def test_hash_command_without_valid_hash_shows_help():
    upd, msg = make_update("/hash nothing")
    bot.rate_limiter = bot.UserRateLimiter(100)
    asyncio.run(bot.hash_command(upd, SimpleNamespace(args=["nothing"])))
    assert "certutil" in msg.reply_text.await_args.args[0]
