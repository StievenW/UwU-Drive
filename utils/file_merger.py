import os
import tempfile
import hashlib
import magic
from pathlib import Path
import shutil
from typing import List, Dict
import mimetypes

class SafeFileMerger:
    MAX_CHUNKS = 4  # Maximum chunks allowed to merge
    ALLOWED_MIME_TYPES = {
        'image/': ['jpeg', 'png', 'gif', 'webp'],
        'video/': ['mp4', 'webm'],
        'audio/': ['mp3', 'wav', 'ogg'],
        'application/pdf': None
    }
    
    DANGEROUS_PATTERNS = [
        b'%PDF-1.0',  # Old PDF versions potentially dangerous
        b'<?php',     # PHP code
        b'<script',   # JavaScript
        b'#!/',       # Shell scripts
        b'.exe',      # Executable files
        b'TVqQAA'     # DOS/PE executables (base64)
    ]
    
    def __init__(self, temp_dir: Path):
        self.temp_dir = temp_dir
    
    def verify_mime_type(self, file_path: str) -> bool:
        """Verify file mime type is allowed"""
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        
        # Additional check using mimetypes
        guessed_type = mimetypes.guess_type(file_path)[0]
        if guessed_type and guessed_type != file_type:
            return False
        
        for allowed_type, subtypes in self.ALLOWED_MIME_TYPES.items():
            if file_type.startswith(allowed_type):
                if subtypes is None:  # Allow all subtypes
                    return True
                return any(subtype in file_type for subtype in subtypes)
        return False
    
    def scan_file(self, file_path: str) -> bool:
        """Scan file for dangerous patterns"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(8192)  # Read first 8KB for header checks
                
                # Check for dangerous patterns
                for pattern in self.DANGEROUS_PATTERNS:
                    if pattern in content:
                        return False
                
                # Additional security checks
                if content.startswith(b'MZ'):  # Executable
                    return False
                if b'\0\0\0\0\0' in content:  # Suspicious null bytes
                    return False
                    
            return True
            
        except Exception as e:
            print(f"File scan error: {e}")
            return False
            
    def merge_chunks(self, chunk_paths: List[str], total_size: int) -> Dict:
        """Safely merge file chunks with security checks"""
        if len(chunk_paths) > self.MAX_CHUNKS:
            raise ValueError("Too many chunks to merge")
            
        # Create temporary file for merging
        with tempfile.NamedTemporaryFile(delete=False, dir=self.temp_dir) as temp_file:
            merged_size = 0
            file_hash = hashlib.sha256()
            
            try:
                # First pass: verify all chunks
                for chunk_path in chunk_paths:
                    if not self.verify_mime_type(chunk_path):
                        raise ValueError(f"Invalid file type detected in {chunk_path}")
                        
                    if not self.scan_file(chunk_path):
                        raise ValueError(f"Malicious content detected in {chunk_path}")
                
                # Second pass: merge chunks
                for chunk_path in chunk_paths:
                    with open(chunk_path, 'rb') as chunk:
                        while True:
                            data = chunk.read(8192)
                            if not data:
                                break
                            temp_file.write(data)
                            file_hash.update(data)
                            merged_size += len(data)
                
                # Verify final size
                if merged_size != total_size:
                    raise ValueError("Size mismatch in merged file")
                
                # Final security check on merged file
                temp_file.flush()
                if not self.verify_mime_type(temp_file.name) or not self.scan_file(temp_file.name):
                    raise ValueError("Security check failed on merged file")
                    
                return {
                    'path': temp_file.name,
                    'hash': file_hash.hexdigest(),
                    'size': merged_size
                }
                
            except Exception as e:
                # Cleanup on error
                try:
                    os.unlink(temp_file.name)
                except:
                    pass
                raise e
    
    def cleanup(self, file_path: str):
        """Safely remove temporary file"""
        try:
            if os.path.exists(file_path):
                os.unlink(file_path)
        except Exception as e:
            print(f"Error cleaning up file: {e}")
