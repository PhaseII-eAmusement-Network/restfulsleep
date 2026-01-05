import tarfile
import os
from datetime import datetime
from typing import Any, Dict
from flask_restful import Resource
from flask import request

from api.constants import APIConstants
from api.data.endpoints.share import ShareData
from api.data.endpoints.user import UserData
from api.external.backblaze import BackBlazeCDN
from api.external.badmaniac import BadManiac

from PIL import Image

class ShareServer:
    SERVER_ENDPOINT = None
    PUBLIC_PATH = None
    UPLOAD_TMP_PATH = None

    @staticmethod
    def updateConfig(share_config: Dict[str, Any]) -> None:
        ShareServer.SERVER_ENDPOINT = share_config.get('upload-endpoint', '')
        ShareServer.PUBLIC_PATH = share_config.get('public-path', '')
        ShareServer.UPLOAD_TMP_PATH = share_config.get('upload-tmp-path', '')

class shareServerStatus(Resource):
    def get(self):
        response_data = {
            "status": 200,
            "message": ""
        }
        return response_data, 200

class shareNewSession(Resource):
    def post(self):
        session_id = ShareData.getNextSession()
        response_data = {
            "status": 200,
            "message": "",
            "session": session_id
        }
        return response_data, 200

class shareBeginUpload(Resource):
    def post(self, session_id, video_id):
        upload_endpoint = ShareServer.SERVER_ENDPOINT

        if upload_endpoint:
            response_data = {
                "status": 200,
                "message": "",
                "url": f'{upload_endpoint}/share/videoUpload/{session_id}/{video_id}'
            }
        else: 
            response_data = {
                "status": 500,
                "message": "Share server not ready!",
                "url": ""
            }

        return response_data, 200
    
class shareVideoUpload(Resource):
    def put(self, session_id, video_id):
        if request.data:
            uploadState = BackBlazeCDN().uploadUserVideo(request.data, session_id, video_id)
            if uploadState:
                return 200
            else:
                return {
                    "status": 500,
                    "message": "Share server not ready!"
                }

        return 500

class shareEndUpload(Resource):
    def post(self, session_id, video_id):
        public_path = ShareServer.PUBLIC_PATH
        update_status = UserData.updateUserPlayVideoData(session_id, {"status": "uploaded", "url": f"{public_path}/{session_id}.mp4"})

        video = UserData.getUserPlayVideo(session_id)
        user = UserData.getUser(video.get('userid', 0))

        userDiscord = user.get('data', {}).get('discord', {})
        if userDiscord.get('linked', False):
            BadManiac.send_upload_complete(userDiscord.get('id'), public_path, session_id)

        if not update_status:
            response_data = {
                "status": 200,
                "message": ""
            }
        else:
            response_data = {
                "status": 500,
                "message": ""
            }
        return response_data, 200
    
class shareLPACUpload(Resource):
    def post(self, session_id: str):
        upload_content = request.files.get('contentBody', None)
        if not upload_content:
            return APIConstants.badEnd('No content provided.')

        upload_name = str(upload_content.filename)
        if not upload_name.endswith('.tar'):
            return APIConstants.badEnd('Not a tarball!')
        
        if len(upload_name.replace('.tar', '').split('_')) != 3:
            return APIConstants.badEnd('Bad file name.')

        session = UserData.getUserContent(session_id, 'lpac_upload')
        if not session:
            return APIConstants.badEnd('No session found.')
        
        upload_path = f"{ShareServer.UPLOAD_TMP_PATH}/{upload_name}"
        try:
            with open(upload_path, "wb") as f:
                chunk_size = 4096
                while True:
                    chunk = request.files['contentBody'].stream.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    f.write(chunk)
        except:
            return APIConstants.badEnd('Failed to receive file.')
        
        extract_path = f"{ShareServer.UPLOAD_TMP_PATH}/extract"
        filelist = []
        try:
            with tarfile.open(upload_path, 'r') as tar:
                for member in tar.getmembers():
                    # Extract only .jpg files
                    if member.name.lower().endswith('.jpg'):
                        tar.extract(member, path=extract_path)

                        datetime_object = datetime.strptime(member.name.split('_')[1], "%Y%m%d%H%M%S")
                        filelist.append({
                            'filename': member.name,
                            'timestamp': int(datetime_object.timestamp()),
                        })
            os.unlink(upload_path)
        except tarfile.TarError as e:
            return APIConstants.badEnd(e)
        
        for index, file in enumerate(filelist):
            filepath = f"{extract_path}/{file.get('filename')}"
            if os.path.exists(filepath):
                image_id = int(file.get('filename').replace('.jpg', '').split('_')[3])
                with Image.open(filepath) as img:
                    png_path = f"{extract_path}/{file.get('timestamp')}_{image_id}.png"
                    img.save(png_path, format='PNG')
                    file['filename'] = f"{file.get('timestamp')}_{image_id}.png"
                os.unlink(filepath)
                    

                with open(png_path, 'rb') as png_file:
                    b2_path = f"game-upload/{session_id}/{file['filename']}"
                    upload_status = BackBlazeCDN().uploadUserContent(png_file.read(), b2_path)
                    if not upload_status:
                        return APIConstants.badEnd('Failed to upload')
                    file['b2_path'] = b2_path
                os.unlink(png_path)

                filelist[index] = file

        update_status = UserData.updateUserContentData(session_id, 'lpac_upload', {'status': 'uploaded', 'filelist': filelist})
        if update_status:
            return APIConstants.badEnd('Failed to update data!')

        return {"message": f"File uploaded successfully", "path": ""}, 200