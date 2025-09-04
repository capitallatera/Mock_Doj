from pydantic import BaseModel, Field

class Error401(BaseModel):
    detail: str = Field("Unauthorized", json_schema_extra={"example": "Unauthorized"})

class Error403(BaseModel):
    detail: str = Field("Forbidden", json_schema_extra={"example": "Forbidden"})

class Error422(BaseModel):
    detail: str = Field("Validation Error", json_schema_extra={"example": "Validation Error"})

class Error500(BaseModel):
    detail: str = Field("Internal Server Error", json_schema_extra={"example": "Internal Server Error"})

class Default(BaseModel):
    detail: str = Field("An unexpected error occurred", json_schema_extra={"example": "An unexpected error occurred"})
