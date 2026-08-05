import time
import subprocess
import logging
import httpx
from config import TELEGRAM_BOT_TOKEN

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("BotSupervisor")

def main():
    """
    Self-healing supervisor process for Telegram Bot.
    Guarantees that if bot.py exits or encounters network drops, it immediately auto-restarts!
    """
    logger.info("Bot Supervisor started. Monitoring bot.py process...")

    while True:
        try:
            # Clear webhook to enable clean polling
            if TELEGRAM_BOT_TOKEN:
                httpx.get(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/deleteWebhook")

            logger.info("Launching bot.py polling instance...")
            proc = subprocess.run(["python", "bot.py"])
            logger.warning(f"bot.py process exited with code {proc.returncode}. Auto-restarting in 3 seconds...")
            time.sleep(3)
        except Exception as e:
            logger.error(f"Supervisor error: {e}. Retrying in 5 seconds...")
            time.sleep(5)

if __name__ == "__main__":
    main()
