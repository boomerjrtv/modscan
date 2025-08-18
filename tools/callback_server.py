#!/usr/bin/env python3
"""
Callback Server - Simulates ngrok endpoint for blind XSS detection
"""
import asyncio
import sqlite3
from aiohttp import web, ClientSession
import time

class CallbackServer:
    def __init__(self, port=8888):
        self.port = port
        self.callback_db = "xss_callbacks.db"
        self._init_db()
    
    def _init_db(self):
        """Initialize callback database"""
        with sqlite3.connect(self.callback_db) as db:
            db.execute('''
                CREATE TABLE IF NOT EXISTS callbacks (
                    id TEXT PRIMARY KEY,
                    url TEXT,
                    payload TEXT,
                    timestamp REAL,
                    received BOOLEAN DEFAULT 0,
                    received_timestamp REAL
                )
            ''')
    
    async def handle_callback(self, request):
        """Handle incoming XSS callbacks"""
        callback_id = request.match_info.get('callback_id')
        
        # Mark callback as received
        with sqlite3.connect(self.callback_db) as db:
            db.execute('''
                UPDATE callbacks 
                SET received = 1, received_timestamp = ?
                WHERE id = ?
            ''', (time.time(), callback_id))
        
        print(f"🎉 BLIND XSS CALLBACK RECEIVED: {callback_id}")
        print(f"   From: {request.remote}")
        print(f"   User-Agent: {request.headers.get('User-Agent', 'Unknown')}")
        print(f"   Referer: {request.headers.get('Referer', 'None')}")
        
        return web.Response(text="OK")
    
    async def start_server(self):
        """Start the callback server"""
        app = web.Application()
        app.router.add_get('/callback/{callback_id}', self.handle_callback)
        app.router.add_post('/callback/{callback_id}', self.handle_callback)
        
        runner = web.AppRunner(app)
        await runner.setup()
        
        site = web.TCPSite(runner, '0.0.0.0', self.port)
        await site.start()
        
        print(f"🌐 Callback server started on port {self.port}")
        print(f"📡 Listening for blind XSS callbacks...")
        
        # Keep server running
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Server shutting down...")
        finally:
            await runner.cleanup()

if __name__ == "__main__":
    server = CallbackServer()
    asyncio.run(server.start_server())