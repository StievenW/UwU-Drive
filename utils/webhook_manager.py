import threading
import time
from pathlib import Path
from typing import Dict, Set

class WebhookManager:
    def __init__(self, webhook_file: str):
        self.webhook_file = webhook_file
        self.webhooks: list = []
        self.in_use: Dict[str, Set[str]] = {}  # webhook -> set of session_ids
        self.lock = threading.Lock()
        self._load_webhooks()
        
    def _load_webhooks(self):
        """Load webhooks from file"""
        try:
            webhook_path = Path(self.webhook_file)
            if webhook_path.exists():
                with open(webhook_path, 'r') as f:
                    self.webhooks = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error loading webhooks: {e}")
            self.webhooks = []

    def get_available_webhook(self, session_id: str) -> str:
        """Get an available webhook for the session"""
        with self.lock:
            # First try to find a webhook already assigned to this session
            for webhook in self.webhooks:
                if session_id in self.in_use.get(webhook, set()):
                    return webhook
            
            # If none found, find least used webhook
            min_users = float('inf')
            selected_webhook = None
            
            for webhook in self.webhooks:
                users = len(self.in_use.get(webhook, set()))
                if users < min_users:
                    min_users = users
                    selected_webhook = webhook
            
            if selected_webhook:
                if selected_webhook not in self.in_use:
                    self.in_use[selected_webhook] = set()
                self.in_use[selected_webhook].add(session_id)
                return selected_webhook
            
            return None

    def release_webhook(self, webhook: str, session_id: str):
        """Release webhook from session"""
        with self.lock:
            if webhook in self.in_use and session_id in self.in_use[webhook]:
                self.in_use[webhook].remove(session_id)
