package com.hedera.services.bdd.spec.infrastructure.listeners;

/*-
 * ‌
 * Hedera Services Test Clients
 * ​
 * Copyright (C) 2018 - 2021 Hedera Hashgraph, LLC
 * ​
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
 * ‍
 */

public class TokenAccountRegistryRel {
	/* Names of a token and account in a spec registry */
	private final String token, account;

	public TokenAccountRegistryRel(String token, String account) {
		this.token = token;
		this.account = account;
	}

	public String getToken() {
		return token;
	}

	public String getAccount() {
		return account;
	}
}