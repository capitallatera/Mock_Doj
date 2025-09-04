from fastapi import Request

def get_file_url(request: Request, filename: str) -> str:

    return f"/static/{filename}"
