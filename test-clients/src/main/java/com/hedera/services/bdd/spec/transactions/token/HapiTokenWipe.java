package com.hedera.services.bdd.spec.transactions.token;

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

import com.google.common.base.MoreObjects;
import com.hedera.services.bdd.spec.HapiApiSpec;
import com.hedera.services.bdd.spec.transactions.HapiTxnOp;
import com.hedera.services.bdd.spec.transactions.TxnUtils;
import com.hedera.services.usage.token.TokenWipeUsage;
import com.hederahashgraph.api.proto.java.FeeData;
import com.hederahashgraph.api.proto.java.HederaFunctionality;
import com.hederahashgraph.api.proto.java.Key;
import com.hederahashgraph.api.proto.java.TokenWipeAccountTransactionBody;
import com.hederahashgraph.api.proto.java.Transaction;
import com.hederahashgraph.api.proto.java.TransactionBody;
import com.hederahashgraph.api.proto.java.TransactionResponse;
import com.hederahashgraph.fee.SigValueObj;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;

import static com.hedera.services.bdd.spec.transactions.TxnUtils.suFrom;

public class HapiTokenWipe extends HapiTxnOp<HapiTokenWipe> {
	static final Logger log = LogManager.getLogger(HapiTokenWipe.class);

	private String account;
	private String token;
	private long amount;

	@Override
	public HederaFunctionality type() {
		return HederaFunctionality.TokenAccountWipe;
	}

	public HapiTokenWipe(String token, String account, long amount) {
		this.token = token;
		this.account = account;
		this.amount = amount;
	}

	@Override
	protected HapiTokenWipe self() {
		return this;
	}

	@Override
	protected long feeFor(HapiApiSpec spec, Transaction txn, int numPayerKeys) throws Throwable {
		return spec.fees().forActivityBasedOp(
				HederaFunctionality.TokenAccountWipe, this::wipeUsage, txn, numPayerKeys);
	}

	private FeeData wipeUsage(TransactionBody txn, SigValueObj svo) {
		return TokenWipeUsage.newEstimate(txn, suFrom(svo)).get();
	}

	@Override
	protected Consumer<TransactionBody.Builder> opBodyDef(HapiApiSpec spec) throws Throwable {
		var tId = TxnUtils.asTokenId(token, spec);
		var aId = TxnUtils.asId(account, spec);
		TokenWipeAccountTransactionBody opBody = spec
				.txns()
				.<TokenWipeAccountTransactionBody, TokenWipeAccountTransactionBody.Builder>body(
						TokenWipeAccountTransactionBody.class, b -> {
							b.setToken(tId);
							b.setAccount(aId);
							b.setAmount(amount);
						});
		return b -> b.setTokenWipe(opBody);
	}

	@Override
	protected List<Function<HapiApiSpec, Key>> defaultSigners() {
		return List.of(
				spec -> spec.registry().getKey(effectivePayer(spec)),
				spec -> spec.registry().getWipeKey(token));
	}

	@Override
	protected Function<Transaction, TransactionResponse> callToUse(HapiApiSpec spec) {
		return spec.clients().getTokenSvcStub(targetNodeFor(spec), useTls)::wipeTokenAccount;
	}

	@Override
	protected void updateStateOf(HapiApiSpec spec) {
	}

	@Override
	protected MoreObjects.ToStringHelper toStringHelper() {
		MoreObjects.ToStringHelper helper = super.toStringHelper()
				.add("token", token)
				.add("account", account)
				.add("amount", amount);
		return helper;
	}
}
