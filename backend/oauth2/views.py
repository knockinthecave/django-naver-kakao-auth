from django.shortcuts import render, redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from decouple import config
from urllib.parse import urlencode
import requests
import secrets


class NaverOAuthLoginAPIView(APIView):
    def get(self, request):
        state = self.generate_state()
        request.session['state'] = state
        redirect_url = self.get_redirect_url(state)
        return redirect(redirect_url)

    def get_redirect_url(self, state):
        base_url = 'https://nid.naver.com/oauth2.0/authorize'
        params = {
            'response_type': 'code',
            'client_id': config('NAVER_CLIENT_ID'),
            'redirect_uri': config('NAVER_REDIRECT_URL'),
            'state': state,
        }
        return f'{base_url}?{urlencode(params)}'

    def generate_state(self):
        return secrets.token_urlsafe(16)


class NaverOAuthCallbackAPIView(APIView):
    def get(self, request):
        code = request.GET.get('code')
        state = request.GET.get('state')

        if not self.is_valid_request(code, state, request):
            return Response({'error': 'Invalid request parameters.'},
                            status=status.HTTP_400_BAD_REQUEST)

        token_data = self.get_token_data(code, state)
        access_token = token_data.get('access_token')

        if not access_token:
            return Response({'error': 'Failed to retrieve access token.'},
                            status=status.HTTP_400_BAD_REQUEST)

        user_info = self.get_user_info(access_token)
        if not user_info:
            return Response({'error': 'Failed to retrieve user information.'},
                            status=status.HTTP_400_BAD_REQUEST)

        return render(request, 'success.html', {'email': user_info['email']})

    def is_valid_request(self, code, state, request):
        if not code or not state:
            return False

        session_state = request.session.get('state')
        if state != session_state:
            return False

        return True

    def get_token_data(self, code, state):
        token_url = 'https://nid.naver.com/oauth2.0/token'
        payload = {
            'grant_type': 'authorization_code',
            'client_id': config('NAVER_CLIENT_ID'),
            'client_secret': config('NAVER_CLIENT_SECRET'),
            'code': code,
            'state': state,
            'redirect_uri': config('NAVER_REDIRECT_URL'),
        }
        token_response = requests.post(token_url, data=payload)
        return token_response.json()

    def get_user_info(self, access_token):
        user_info_url = 'https://openapi.naver.com/v1/nid/me'
        headers = {'Authorization': f'Bearer {access_token}'}
        user_info_response = requests.get(user_info_url, headers=headers)
        user_info_data = user_info_response.json()

        if user_info_data.get('resultcode') != '00':
            return None

        return {
            'email': user_info_data.get('response').get('email'),
        }


class KakaoOAuthLoginAPIView(APIView):
    def get(self, request):
        state = self.generate_state()
        request.session['state'] = state
        redirect_url = self.get_redirect_url(state)
        return redirect(redirect_url)

    def get_redirect_url(self, state):
        base_url = 'https://kauth.kakao.com/oauth/authorize'
        params = {
            'response_type': 'code',
            'client_id': config('KAKAO_CLIENT_ID'),
            'redirect_uri': config('KAKAO_REDIRECT_URL'),
            'state': state,
        }
        return f'{base_url}?{urlencode(params)}'

    def generate_state(self):
        return secrets.token_urlsafe(16)


class KakaoOAuthCallbackAPIView(APIView):
    def get(self, request):
        code = request.GET.get('code')
        state = request.GET.get('state')

        if not self.is_valid_request(code, state, request):
            return Response({'error': 'Invalid request parameters.'},
                            status=status.HTTP_400_BAD_REQUEST)

        token_data = self.get_token_data(code)
        access_token = token_data.get('access_token')

        if not access_token:
            return Response({'error': 'Failed to retrieve access token.'},
                            status=status.HTTP_400_BAD_REQUEST)

        user_info = self.get_user_info(access_token)
        if not user_info:
            return Response({'error': 'Failed to retrieve user information.'},
                            status=status.HTTP_400_BAD_REQUEST)

        return render(request,
                      'success.html',
                      {'email': user_info['kakao_account']['email']})

    def is_valid_request(self, code, state, request):
        if not code or not state:
            return False

        session_state = request.session.get('state')
        if state != session_state:
            return False

        return True

    def get_token_data(self, code):
        token_url = 'https://kauth.kakao.com/oauth/token'
        headers = {'Content-type': 'application/x-www-form-urlencoded;'
                   'charset=utf-8'}
        payload = {
            'grant_type': 'authorization_code',
            'client_id': config('KAKAO_CLIENT_ID'),
            'redirect_uri': config('KAKAO_REDIRECT_URL'),
            'code': code,
            'client_secret': config('KAKAO_CLIENT_SECRET'),
        }
        token_response = requests.post(token_url,
                                       headers=headers,
                                       data=payload)
        return token_response.json()

    def get_user_info(self, access_token):
        user_info_url = 'https://kapi.kakao.com/v2/user/me'
        headers = {'Authorization': f'Bearer {access_token}'}
        user_info_response = requests.get(user_info_url, headers=headers)
        user_info_data = user_info_response.json()

        return user_info_data
