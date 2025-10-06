import os
import secrets
import time
from typing import Tuple, Optional, Dict
from dataclasses import dataclass
from argon2.low_level import hash_secret_raw, Type
from ecdsa import NIST256p
from ecdsa.ellipticcurve import Point


@dataclass
class RegistrationData:
    username: str
    salt: bytes
    public_key_bytes: bytes
    
    def to_dict(self) -> Dict:
        return {
            'username': self.username,
            'salt': self.salt.hex(),
            'public_key': self.public_key_bytes.hex()
        }


@dataclass
class CommitmentData:
    R_bytes: bytes
    
    def to_dict(self) -> Dict:
        return {'R': self.R_bytes.hex()}


@dataclass
class ChallengeData:
    challenge: bytes
    round_num: int
    expires_at: float
    
    def to_dict(self) -> Dict:
        return {
            'challenge': self.challenge.hex(),
            'round_num': self.round_num,
            'expires_at': self.expires_at
        }
    
    def is_expired(self) -> bool:
        return time.time() > self.expires_at


@dataclass
class ResponseData:
    s: int
    round_num: int
    
    def to_dict(self) -> Dict:
        return {
            's': str(self.s),
            'round_num': self.round_num
        }


@dataclass
class AuthResult:
    success: bool
    elapsed_time: float
    rounds_completed: int
    security_bits: int
    message: str = ""
    
    def __str__(self):
        status = "✓ SUCCESS" if self.success else "✗ FAILED"
        return (f"{status} | Time: {self.elapsed_time:.3f}s | "
                f"Rounds: {self.rounds_completed} | "
                f"Security: {self.security_bits} bits")


class SchnorrClient:
    
    def __init__(self, rounds: int = 3, verbose: bool = False):
        if rounds < 1:
            raise ValueError("rounds must be >= 1")
        
        self.rounds = rounds
        self.verbose = verbose
        self.curve = NIST256p
        self.generator = self.curve.generator
        self.order = self.curve.order
        
        self._argon2_params = {
            'time_cost': 3,
            'memory_cost': 65536,
            'parallelism': 4,
            'hash_len': 32,
            'type': Type.ID
        }
        
        self._current_private_key: Optional[int] = None
    
    def _log(self, msg: str):
        if self.verbose:
            print(f"[CLIENT] {msg}")
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        return hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            **self._argon2_params
        )
    
    def _password_to_private_key(self, password: str, salt: bytes) -> int:
        key_material = self._derive_key(password, salt)
        private_value = int.from_bytes(key_material, byteorder='big')
        return (private_value % (self.order - 1)) + 1
    
    def _point_to_bytes(self, point: Point) -> bytes:
        x_bytes = point.x().to_bytes(32, byteorder='big')
        y_bytes = point.y().to_bytes(32, byteorder='big')
        return b'\x04' + x_bytes + y_bytes
    
    def _bytes_to_point(self, point_bytes: bytes) -> Point:
        if len(point_bytes) != 65 or point_bytes[0] != 0x04:
            raise ValueError("Invalid point format")
        
        x = int.from_bytes(point_bytes[1:33], byteorder='big')
        y = int.from_bytes(point_bytes[33:65], byteorder='big')
        
        return Point(self.curve.curve, x, y)
    
    def register_user(self, username: str, password: str) -> RegistrationData:
        self._log(f"Registration: {username}")
        
        salt = os.urandom(16)
        private_key = self._password_to_private_key(password, salt)
        public_key_point = private_key * self.generator
        public_key_bytes = self._point_to_bytes(public_key_point)
        
        return RegistrationData(
            username=username,
            salt=salt,
            public_key_bytes=public_key_bytes
        )
    
    def generate_commitment(self, private_key: int) -> Tuple[int, CommitmentData]:
        k = secrets.randbelow(self.order - 1) + 1
        R = k * self.generator
        R_bytes = self._point_to_bytes(R)
        
        return k, CommitmentData(R_bytes=R_bytes)
    
    def compute_response(self, private_key: int, k: int, challenge: bytes) -> ResponseData:
        c = int.from_bytes(challenge, byteorder='big')
        s = (k + c * private_key) % self.order
        
        return ResponseData(s=s, round_num=0)
    
    def login(self, username: str, password: str, server: 'SchnorrServer') -> AuthResult:
        self._log(f"Login: {username}")
        start_time = time.time()
        
        try:
            salt = server.get_user_salt(username)
            if salt is None:
                return AuthResult(
                    success=False,
                    elapsed_time=time.time() - start_time,
                    rounds_completed=0,
                    security_bits=0,
                    message="User not found"
                )
            
            self._current_private_key = self._password_to_private_key(password, salt)
            
            test_public_point = self._current_private_key * self.generator
            test_pub_bytes = self._point_to_bytes(test_public_point)
            registered_pub_bytes = server.get_user_public_key(username)
            
            if test_pub_bytes != registered_pub_bytes:
                return AuthResult(
                    success=False,
                    elapsed_time=time.time() - start_time,
                    rounds_completed=0,
                    security_bits=0,
                    message="Wrong password"
                )
            
            rounds_completed = 0
            
            for round_num in range(1, self.rounds + 1):
                self._log(f"Round {round_num}/{self.rounds}")
                
                k, commitment = self.generate_commitment(self._current_private_key)
                challenge_data = server.generate_challenge(username, commitment)
                
                if challenge_data.is_expired():
                    return AuthResult(
                        success=False,
                        elapsed_time=time.time() - start_time,
                        rounds_completed=rounds_completed,
                        security_bits=256 * rounds_completed,
                        message=f"Challenge expired at round {round_num}"
                    )
                
                response = self.compute_response(
                    self._current_private_key,
                    k,
                    challenge_data.challenge
                )
                response.round_num = round_num
                
                round_ok = server.verify_response(username, response)
                
                if not round_ok:
                    break
                
                rounds_completed += 1
            
            elapsed = time.time() - start_time
            success = (rounds_completed == self.rounds)
            
            return AuthResult(
                success=success,
                elapsed_time=elapsed,
                rounds_completed=rounds_completed,
                security_bits=256 * rounds_completed,
                message="Authentication successful" if success else f"Failed at round {rounds_completed+1}"
            )
            
        except Exception as e:
            elapsed = time.time() - start_time
            return AuthResult(
                success=False,
                elapsed_time=elapsed,
                rounds_completed=0,
                security_bits=0,
                message=f"Error: {str(e)}"
            )


class SchnorrServer:
    
    def __init__(self, rounds: int = 3, challenge_ttl: int = 60, verbose: bool = False):
        if rounds < 1:
            raise ValueError("rounds must be >= 1")
        if challenge_ttl < 1:
            raise ValueError("challenge_ttl must be >= 1")
        
        self.rounds = rounds
        self.challenge_ttl = challenge_ttl
        self.verbose = verbose
        self.curve = NIST256p
        self.generator = self.curve.generator
        self.order = self.curve.order
        
        self._users: Dict[str, Dict] = {}
        self._sessions: Dict[str, Dict] = {}
    
    def _log(self, msg: str):
        if self.verbose:
            print(f"[SERVER] {msg}")
    
    def _point_to_bytes(self, point: Point) -> bytes:
        x_bytes = point.x().to_bytes(32, byteorder='big')
        y_bytes = point.y().to_bytes(32, byteorder='big')
        return b'\x04' + x_bytes + y_bytes
    
    def _bytes_to_point(self, point_bytes: bytes) -> Point:
        if len(point_bytes) != 65 or point_bytes[0] != 0x04:
            raise ValueError("Invalid point format")
        
        x = int.from_bytes(point_bytes[1:33], byteorder='big')
        y = int.from_bytes(point_bytes[33:65], byteorder='big')
        
        return Point(self.curve.curve, x, y)
    
    def _cleanup_expired_challenges(self, username: str):
        if username not in self._sessions:
            return
        
        current_time = time.time()
        expired_rounds = []
        
        for round_num, round_data in self._sessions[username].items():
            if current_time > round_data['expires_at']:
                expired_rounds.append(round_num)
        
        for round_num in expired_rounds:
            del self._sessions[username][round_num]
            self._log(f"Expired challenge removed: user={username}, round={round_num}")
    
    def store_user(self, username: str, public_key_bytes: bytes, salt: bytes) -> bool:
        try:
            public_point = self._bytes_to_point(public_key_bytes)
            
            self._users[username] = {
                'salt': salt,
                'public_key_bytes': public_key_bytes,
                'public_key_point': public_point,
                'registered_at': time.time()
            }
            self._log(f"User registered: {username}")
            return True
        except Exception as e:
            self._log(f"Registration error: {e}")
            return False
    
    def get_user_salt(self, username: str) -> Optional[bytes]:
        user = self._users.get(username)
        return user['salt'] if user else None
    
    def get_user_public_key(self, username: str) -> Optional[bytes]:
        user = self._users.get(username)
        return user['public_key_bytes'] if user else None
    
    def generate_challenge(self, username: str, commitment: CommitmentData) -> ChallengeData:
        self._cleanup_expired_challenges(username)
        
        if username not in self._sessions:
            self._sessions[username] = {}
        
        round_num = len(self._sessions[username]) + 1
        challenge = os.urandom(32)
        
        try:
            R_point = self._bytes_to_point(commitment.R_bytes)
        except Exception as e:
            raise ValueError("Invalid commitment point")
        
        current_time = time.time()
        expires_at = current_time + self.challenge_ttl
        
        self._sessions[username][round_num] = {
            'R_bytes': commitment.R_bytes,
            'R_point': R_point,
            'challenge': challenge,
            'timestamp': current_time,
            'expires_at': expires_at
        }
        
        self._log(f"Challenge generated: user={username}, round={round_num}, ttl={self.challenge_ttl}s")
        
        return ChallengeData(
            challenge=challenge,
            round_num=round_num,
            expires_at=expires_at
        )
    
    def verify_response(self, username: str, response: ResponseData) -> bool:
        try:
            user = self._users.get(username)
            session = self._sessions.get(username)
            
            if not user or not session or response.round_num not in session:
                self._log(f"Verification failed: missing user or session data")
                return False
            
            round_data = session[response.round_num]
            
            current_time = time.time()
            if current_time > round_data['expires_at']:
                self._log(f"Verification failed: challenge expired (round {response.round_num})")
                return False
            
            s = response.s
            R_point = round_data['R_point']
            c_bytes = round_data['challenge']
            public_key_point = user['public_key_point']
            
            if s <= 0 or s >= self.order:
                self._log(f"Verification failed: invalid s value")
                return False
            
            c = int.from_bytes(c_bytes, byteorder='big') % self.order
            
            left_point = s * self.generator
            c_times_pubkey = c * public_key_point
            right_point = R_point + c_times_pubkey
            
            points_equal = (left_point.x() == right_point.x() and 
                          left_point.y() == right_point.y())
            
            if points_equal:
                time_remaining = round_data['expires_at'] - current_time
                self._log(f"Round {response.round_num} verified (time remaining: {time_remaining:.1f}s)")
            else:
                self._log(f"Verification failed: point mismatch")
            
            return points_equal
            
        except Exception as e:
            self._log(f"Verification error: {e}")
            return False
    
    def cleanup_session(self, username: str):
        if username in self._sessions:
            del self._sessions[username]
            self._log(f"Session cleaned: {username}")
    
    def get_challenge_info(self, username: str, round_num: int) -> Optional[Dict]:
        if username not in self._sessions or round_num not in self._sessions[username]:
            return None
        
        round_data = self._sessions[username][round_num]
        current_time = time.time()
        
        return {
            'timestamp': round_data['timestamp'],
            'expires_at': round_data['expires_at'],
            'time_remaining': max(0, round_data['expires_at'] - current_time),
            'is_expired': current_time > round_data['expires_at']
        }