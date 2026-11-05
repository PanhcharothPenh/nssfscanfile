"""Supervisor for polling mode: restarts bot.py if it crashes (with back-off).

Use this OR the webhook deployment (server.py on Vercel), never both: Telegram
allows only one update source per bot token.
"""
import logging
import subprocess
import sys
import time
from pathlib import Path

logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger("BotSupervisor")

BOT_PATH = str(Path(__file__).resolve().with_name("bot.py"))


def main() -> None:
    delay = 3
    while True:
        started = time.monotonic()
        logger.info("Launching bot.py ...")
        code = subprocess.run([sys.executable, BOT_PATH]).returncode
        ran = time.monotonic() - started
        # reset the back-off if the bot ran for a while, otherwise double it (max 60s)
        delay = 3 if ran > 120 else min(delay * 2, 60)
        logger.warning("bot.py exited with code %s after %.0fs. Restarting in %ss", code, ran, delay)
        time.sleep(delay)


if __name__ == "__main__":
    main()
