from django.urls import path
from .views import (NaverOAuthLoginAPIView, NaverOAuthCallbackAPIView,
                    KakaoOAuthLoginAPIView, KakaoOAuthCallbackAPIView)

urlpatterns = [
    path('naver/login/',
         NaverOAuthLoginAPIView.as_view(),
         name='naver-login'),
    path('naver/callback/',
         NaverOAuthCallbackAPIView.as_view(),
         name='naver-callback'),
    path('kakao/login/',
         KakaoOAuthLoginAPIView.as_view(),
         name='kakao-login'),
    path('kakao/callback/',
         KakaoOAuthCallbackAPIView.as_view(),
         name='kakao-callback'),
]
