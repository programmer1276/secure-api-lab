# Защищенный REST API (Лабораторная работа)

## Описание проекта
Простое, но защищенное веб-API на Python (Flask), демонстрирующее применение принципов безопасности OWASP Top 10 и интеграцию инструментов безопасности в CI/CD.

## Стек технологий
- **Backend**: Python 3.11, Flask
- **База данных**: SQLite (через SQLAlchemy ORM)
- **Безопасность**: PyJWT (аутентификация), Werkzeug (хэширование паролей), Bleach (санитизация)
- **CI/CD**: GitHub Actions, Bandit (SAST), pip-audit (SCA)

## Описание API и примеры вызова

### 1. Регистрация пользователя
```bash
curl -X POST http://127.0.0.1:5000/auth/register \
-H "Content-Type: application/json" \
-d '{"username": "testuser", "password": "SecurePass123!"}'
