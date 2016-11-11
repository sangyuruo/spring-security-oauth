/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.token;

import java.util.Collections;
import java.util.List;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

/**
 * A chain of OAuth2 access token providers. This implementation will iterate through its chain to find the first
 * provider that supports the resource and use it to obtain the access token. Note that the order of the chain is
 * relevant.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class AccessTokenProviderChain extends OAuth2AccessTokenSupport implements AccessTokenProvider {

	private final List<AccessTokenProvider> chain;

	private ClientTokenServices clientTokenServices;

	public AccessTokenProviderChain(List<? extends AccessTokenProvider> chain) {
		this.chain = chain == null ? Collections.<AccessTokenProvider> emptyList() : Collections
				.unmodifiableList(chain);
	}

	/**
	 * Token services for long-term persistence of access tokens.
	 * 
	 * @param clientTokenServices the clientTokenServices to set
	 */
	public void setClientTokenServices(ClientTokenServices clientTokenServices) {
		this.clientTokenServices = clientTokenServices;
	}

	public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
		for (AccessTokenProvider tokenProvider : chain) {
			if (tokenProvider.supportsResource(resource)) {
				return true;
			}
		}
		return false;
	}

	public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
		for (AccessTokenProvider tokenProvider : chain) {
			if (tokenProvider.supportsRefresh(resource)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 获取AccessToken<br>
	 * 1.排除 anonymous token<br>
	 * 2.先从请求(会话？)中获取历史的accessToken<br>
	 * 3.没有的话，则从clientTokenServices(数据库？)获取历史的accessToken<br>
	 * 4.判断accessToken是否过期<br>
	 * 4.1 对于过期的accessToken，<br>
	 *     首先：在数据库(固态存储资源？)中删除过期的accessToken<br>
	 *     获取refresh token<br>
	 *     使用refresh token获取accessToken<br>
	 * 4.2 未过期，则直接使用<br>
	 * 5.如果还是没有取到的话，则从oauth2流程获取<br>
	 * 6.保存accessToken到数据库中
	 */
	public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails resource, AccessTokenRequest request)
			throws UserRedirectRequiredException, AccessDeniedException {

		OAuth2AccessToken accessToken = null;
		OAuth2AccessToken existingToken = null;
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();

		if (auth instanceof AnonymousAuthenticationToken) {
			//排除 anonymous token?
			if (!resource.isClientOnly()) {
				throw new InsufficientAuthenticationException(
						"Authentication is required to obtain an access token (anonymous not allowed)");
			}
		}

		if (resource.isClientOnly() || (auth != null && auth.isAuthenticated())) {
			//先从请求(会话？)中获取历史的accessToken
			existingToken = request.getExistingToken();
			if (existingToken == null && clientTokenServices != null) {
				//从clientTokenServices(数据库？)获取历史的accessToken
				existingToken = clientTokenServices.getAccessToken(resource, auth);
			}

			if (existingToken != null) {
				if (existingToken.isExpired()) {
					//判断是否过期
					if (clientTokenServices != null) {
						//在数据库(固态存储资源？)中删除过期的accessToken
						clientTokenServices.removeAccessToken(resource, auth);
					}
					//获取refresh token
					OAuth2RefreshToken refreshToken = existingToken.getRefreshToken();
					if (refreshToken != null) {
						//使用refresh token获取accessToken
						accessToken = refreshAccessToken(resource, refreshToken, request);
					}
				}
				else {
					accessToken = existingToken;
				}
			}
		}
		// Give unauthenticated users a chance to get a token and be redirected

		if (accessToken == null) {
			// looks like we need to try to obtain a new token. 
			// 从oauth2流程获取
			accessToken = obtainNewAccessTokenInternal(resource, request);

			if (accessToken == null) {
				throw new IllegalStateException("An OAuth 2 access token must be obtained or an exception thrown.");
			}
		}

		if (clientTokenServices != null && (resource.isClientOnly() || auth != null && auth.isAuthenticated())) {
			//保存accessToken到数据库中
			clientTokenServices.saveAccessToken(resource, auth, accessToken);
		}

		return accessToken;
	}

	/**
	 * 根据details在chain中选择合适的 tokenProvider<br>
	 * 使用该tokenProvider走oauth2流程获取新的accessToken<br>
	 */
	protected OAuth2AccessToken obtainNewAccessTokenInternal(OAuth2ProtectedResourceDetails details,
			AccessTokenRequest request) throws UserRedirectRequiredException, AccessDeniedException {

		if (request.isError()) {
			// there was an oauth error...
			throw OAuth2Exception.valueOf(request.toSingleValueMap());
		}

		for (AccessTokenProvider tokenProvider : chain) {
			if (tokenProvider.supportsResource(details)) {
				return tokenProvider.obtainAccessToken(details, request);
			}
		}

		throw new OAuth2AccessDeniedException("Unable to obtain a new access token for resource '" + details.getId()
				+ "'. The provider manager is not configured to support it.", details);
	}

	/**
	 * Obtain a new access token for the specified resource using the refresh token.
	 * 
	 * @param resource The resource.
	 * @param refreshToken The refresh token.
	 * @return The access token, or null if failed.
	 * @throws UserRedirectRequiredException
	 */
	public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
			OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException {
		for (AccessTokenProvider tokenProvider : chain) {
			if (tokenProvider.supportsRefresh(resource)) {
				return tokenProvider.refreshAccessToken(resource, refreshToken, request);
			}
		}
		throw new OAuth2AccessDeniedException("Unable to obtain a new access token for resource '" + resource.getId()
				+ "'. The provider manager is not configured to support it.", resource);
	}

}
