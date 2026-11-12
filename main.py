import os
import sqlite3
from pathlib import Path
from datetime import date, datetime, timedelta, timezone

import pandas as pd
import jwt
from pwdlib import PasswordHash #ИМПОРТИРУЮ ВСЕ НУЖНЫЕ МНЕ БИБЛИОТЕКИ

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, field_validator
import re
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# =========================
# CONFIGURATION
# =========================
# Задаю пути к файлам, чтобы сервер знал, где лежат данные и база
BASE_DIR = Path(__file__).resolve().parent
FORECAST_FILE = BASE_DIR / "my_forecast.csv"
ROUTES_FILE = BASE_DIR / "routes.csv"
DATABASE_FILE = BASE_DIR / "users.db"

# Секретный ключ для подписи токенов. Если его украдут то смогут подделать пропуск
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CHANGE_ME_TO_A_RANDOM_SECRET")
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60  # Токен живет 1 час, потом сгорает

# "Мясорубка" для паролей: превращает пароль в хэш, чтобы не хранить его в открытом виде
password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

app = FastAPI(
    title="Airline Demand Forecast API",
    description="API for predicting airline ticket demand",
    version="1.0.0"
)

# =========================
# CORS
# =========================
# Разрешаю запросы с любого сайта, чтобы браузер не блокировал мой фронтенд
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# =========================
# LOAD CSV DATA
# =========================
# Загружаю CSV-файлы в память при старте сервера, чтобы потом искать в них данные за миллисекунды
try:
    forecast_df = pd.read_csv(FORECAST_FILE)
    routes_df = pd.read_csv(ROUTES_FILE)

    # Превращаю колонку с датой в настоящие даты, чтобы можно было сравнивать
    forecast_df["date"] = pd.to_datetime(
        forecast_df["date"], errors="coerce"
    ).dt.date
except Exception as e:
    raise RuntimeError(f"Error loading CSV files: {e}")

# =========================
# DATABASE
# =========================
# Функция для подключения к базе. Возвращает соединение, через которое делаю запросы
def get_db():
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row  # Чтобы данные возвращались как словарь
    return connection

# Создаю таблицу пользователей, если её еще нет
def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

init_db()

# =========================
# REQUEST MODELS
# =========================
# Шаблон для регистрации: проверяю, что логин от 3 до 50 символов, а пароль от 8 до 128
class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128, description="Пароль от 8 до 128 символов")

    # Добавил проверку на сложность пароля, чтобы нельзя было зарегистрироваться с "123456"
    @field_validator('password')
    def check_password_strength(cls, v):
        if not re.search(r"[A-Z]", v):
            raise ValueError('Пароль должен содержать хотя бы одну заглавную букву')
        if not re.search(r"[a-z]", v):
            raise ValueError('Пароль должен содержать хотя бы одну строчную букву')
        if not re.search(r"\d", v):
            raise ValueError('Пароль должен содержать хотя бы одну цифру')
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError('Пароль должен содержать хотя бы один спецсимвол (!@#$%^&*)')
        return v

# Шаблон для входа: нужны только логин и пароль
class LoginRequest(BaseModel):
    username: str
    password: str

# Шаблон для прогноза: маршрут, дата и цена (цена обязательно больше нуля)
class PredictRequest(BaseModel):
    route: str
    date: date
    price: float = Field(gt=0)

# =========================
# AUTHENTICATION
# =========================
# Создаю JWT-токен (пропуск). Внутри него логин и время жизни, подписано секретным ключом
def create_access_token(username: str):
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": username,
        "exp": expire
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# "Охранник": проверяет токен при каждом запросе. Если токен невалидный не пускает
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_error = HTTPException(
        status_code=401,
        detail="Invalid or expired authentication token",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("sub")

        if not username:
            raise credentials_error

        with get_db() as db:
            user = db.execute(
                "SELECT id, username FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user is None:
            raise credentials_error

        return user

    except jwt.InvalidTokenError:
        raise credentials_error

# =========================
# REGISTER
# =========================
# Эндпоинт для регистрации: хэширую пароль и записываю в базу
@app.post("/register")
def register(data: RegisterRequest):
    hashed_password = password_hash.hash(data.password)

    try:
        with get_db() as db:
            db.execute(
                """
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
                """,
                (data.username, hashed_password)
            )

        return {
            "message": "User registered successfully"
        }

    except sqlite3.IntegrityError:
        # Если логин уже есть, база выдает ошибку то я ловлю её и возвращаю 409
        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )

# =========================
# LOGIN
# =========================
# Эндпоинт для входа: ищу пользователя, проверяю хэш пароля и выдаю токен
@app.post("/login")
def login(data: LoginRequest):
    with get_db() as db:
        user = db.execute(
            """
            SELECT username, password_hash
            FROM users
            WHERE username = ?
            """,
            (data.username,)
        ).fetchone()

    if user is None or not password_hash.verify(
        data.password,
        user["password_hash"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )

    token = create_access_token(user["username"])

    return {
        "access_token": token,
        "token_type": "bearer"
    }

# =========================
# DEMAND PREDICTION
# =========================
# Главный эндпоинт: защищен токеном, ищет данные в CSV и считает прогноз
@app.post("/predict")
def predict(
    request: PredictRequest,
    current_user=Depends(get_current_user)
):
    # 1. Ищу строку с прогнозом по маршруту и дате
    forecast = forecast_df[
        (forecast_df["route"] == request.route) &
        (forecast_df["date"] == request.date)
    ]

    if forecast.empty:
        raise HTTPException(
            status_code=404,
            detail="Forecast not found for this route and date"
        )

    forecast_row = forecast.iloc[0]

    # 2. Ищу параметры маршрута (базовую цену и чувствительность) в справочнике
    route_data = routes_df[
        routes_df["route"] == request.route
    ]

    if route_data.empty:
        raise HTTPException(
            status_code=404,
            detail="Route information not found"
        )

    route_row = route_data.iloc[0]

    base_price = float(route_row["base_price"])
    price_sensitivity = float(route_row["price_sensitivity"])

    seats = int(forecast_row["seats"])

    # 3. Считаю спрос по формуле. Если цена ниже базовой, спрос растет, если выше то падает
    base_demand = float(forecast_row["0.5_base_demand"])

    desired_demand = (
        base_demand -
        price_sensitivity * (request.price - base_price)
    )

    # Защита от отрицательного спроса и от переполнения самолета
    desired_demand = max(0, desired_demand)

    sold = min(seats, desired_demand)

    # 4. Собираю все 9 квантилей для графика
    quantiles = {}

    for q in range(1, 10):
        quantile = f"0.{q}"

        demand_column = f"{quantile}_price_demand"
        price_column = f"{quantile}_price"

        if (
            demand_column not in forecast_df.columns or
            price_column not in forecast_df.columns
        ):
            raise HTTPException(
                status_code=500,
                detail=f"Missing columns for quantile {quantile}"
            )

        # Пересчитываю спрос для графика без ограничения по местам, чтобы было видно, упирается ли спрос в seats
        q_base_demand = float(forecast_row[f"{quantile}_base_demand"])
        q_price = float(forecast_row[price_column])

        q_desired = q_base_demand - price_sensitivity * (request.price - base_price)
        q_demand = max(0.0, q_desired)  # Без min(seats, ...) чтобы показать реальный спрос

        quantiles[quantile] = {
            "demand": q_demand,
            "price": q_price
        }

    # 5. Возвращаю ответ: маршрут, дату, места, проданные билеты и квантили для графика
    return {
        "route": request.route,
        "date": request.date.isoformat(),
        "seats": seats,
        "sold": round(sold, 2),
        "quantiles": quantiles
    }

# =========================
# HEALTH CHECK
# =========================
# Отдаю index.html, когда захожу на главную страницу сайта
@app.get("/")
async def read_index():
    return FileResponse("index.html")
