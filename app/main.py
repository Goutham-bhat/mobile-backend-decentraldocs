# app/main.py

from fastapi import FastAPI, UploadFile, File, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response
from dotenv import load_dotenv
import os
import httpx
import logging
import io
import asyncio

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(
    title="DecentralDocs Backend API",
    description="API for decentralized document storage (IPFS via Pinata) and OCR.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

PINATA_API_KEY = os.getenv("PINATA_API_KEY")
PINATA_SECRET_API_KEY = os.getenv("PINATA_SECRET_API_KEY")
PINATA_UPLOAD_URL = "https://api.pinata.cloud/pinning/pinFileToIPFS"
PINATA_GATEWAY = "https://gateway.pinata.cloud/ipfs/"

@app.on_event("startup")
async def startup_event():
    if not PINATA_API_KEY or not PINATA_SECRET_API_KEY:
        logger.error("PINATA_API_KEY or PINATA_SECRET_API_KEY not loaded from environment variables!")
        logger.error("Please ensure your .env file is correctly configured in the backend's root directory.")
    else:
        logger.info("Pinata API keys loaded successfully.")

async def upload_file_to_pinata(data: bytes, filename: str) -> str:
    if not PINATA_API_KEY or not PINATA_SECRET_API_KEY:
        raise ValueError("Pinata API keys are not configured on the server.")

    try:
        async with httpx.AsyncClient() as client:
            files = {"file": (filename, data)}
            pinata_response = await client.post(
                PINATA_UPLOAD_URL,
                files=files,
                headers={
                    "pinata_api_key": PINATA_API_KEY,
                    "pinata_secret_api_key": PINATA_SECRET_API_KEY,
                },
                timeout=300.0
            )
            pinata_response.raise_for_status()
            ipfs_hash = pinata_response.json().get('IpfsHash')
            if not ipfs_hash:
                raise ValueError("Pinata response missing IpfsHash")
            logger.info(f"File '{filename}' uploaded to Pinata: {ipfs_hash}")
            return ipfs_hash
    except httpx.HTTPStatusError as e:
        logger.error(f"Pinata HTTP error during upload for '{filename}': {e.response.status_code} - {e.response.text}")
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Pinata API upload error: {e.response.text}"
        )
    except httpx.RequestError as e:
        logger.error(f"Network error to Pinata during upload for '{filename}': {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not connect to Pinata API for upload: {e}"
        )
    except Exception as e:
        logger.error(f"Unexpected error during Pinata upload for '{filename}': {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred during IPFS upload: {str(e)}"
        )

async def get_file_from_pinata_gateway(ipfs_hash: str) -> bytes:
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{PINATA_GATEWAY}{ipfs_hash}", timeout=300.0)
            response.raise_for_status()
            logger.info(f"Retrieved {ipfs_hash} from Pinata gateway.")
            return response.content
    except httpx.HTTPStatusError as e:
        logger.error(f"Failed to fetch {ipfs_hash} from Pinata gateway: {e.response.status_code} - {e.response.text}")
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Error fetching file from IPFS: {e.response.text}"
        )
    except httpx.RequestError as e:
        logger.error(f"Network error to Pinata during retrieval of {ipfs_hash}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not connect to Pinata IPFS gateway: {e}"
        )
    except Exception as e:
        logger.error(f"Unexpected error during Pinata gateway retrieval for {ipfs_hash}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred during IPFS retrieval: {str(e)}"
        )

async def delete_file_from_pinata(ipfs_hash: str) -> bool:
    logger.info(f"Attempting to unpin {ipfs_hash} from Pinata.")
    url = f"https://api.pinata.cloud/pinning/unpin/{ipfs_hash}"
    headers = {
        "pinata_api_key": PINATA_API_KEY,
        "pinata_secret_api_key": PINATA_SECRET_API_KEY
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.delete(url, headers=headers)
            response.raise_for_status()

        logger.info(f"Successfully unpinned {ipfs_hash} from Pinata.")
        return True
    except httpx.HTTPStatusError as e:
        logger.error(f"Failed to unpin {ipfs_hash} from Pinata: {e.response.status_code} - {e.response.text}")
        if e.response.status_code == 404:
            logger.warning(f"File {ipfs_hash} not found on Pinata for unpinning (might already be unpinned). Considering it successful for cleanup.")
            return True
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Pinata unpin error: {e.response.text}"
        )
    except httpx.RequestError as e:
        logger.error(f"Network error to Pinata during unpin of {ipfs_hash}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not connect to Pinata API for unpin: {e}"
        )
    except Exception as e:
        logger.error(f"Unexpected error during Pinata unpin of {ipfs_hash}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred during IPFS unpin: {str(e)}"
        )

@app.get("/")
async def read_root():
    return {"message": "DecentralDocs Backend is running with FastAPI!"}

@app.post("/pin/upload")
async def pin_file_to_ipfs_endpoint(file: UploadFile = File(...)):
    logger.info(f"Request to upload file: {file.filename}, Content-Type: {file.content_type}")
    try:
        file_content = await file.read()
        ipfs_hash = await upload_file_to_pinata(file_content, file.filename)

        # The IPFS hash and filename will be returned to the React Native app.
        # Your React Native app is responsible for storing this info in its local SQLite DB
        # along with any extracted text (from ML Kit) and user details it manages.

        return {"ipfs_hash": ipfs_hash, "filename": file.filename}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error in /pin/upload endpoint for {file.filename}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process file upload: {str(e)}"
        )

@app.get("/download/{ipfs_hash}")
async def download_file_endpoint(ipfs_hash: str):
    logger.info(f"Request to download file with hash: {ipfs_hash}")
    try:
        file_content = await get_file_from_pinata_gateway(ipfs_hash)

        media_type = "application/octet-stream"
        filename = f"downloaded_file_{ipfs_hash[:8]}"

        return StreamingResponse(
            io.BytesIO(file_content),
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error in /download/{ipfs_hash} endpoint: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to download file from IPFS: {str(e)}"
        )

@app.delete("/unpin/{ipfs_hash}")
async def unpin_file_endpoint(ipfs_hash: str):
    logger.info(f"Request to unpin file with hash: {ipfs_hash}")
    try:
        success = await delete_file_from_pinata(ipfs_hash)
        if success:
            return {"message": f"Successfully unpinned {ipfs_hash} from Pinata."}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to unpin {ipfs_hash}."
            )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error in /unpin/{ipfs_hash} endpoint: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process unpin request: {str(e)}"
        )
