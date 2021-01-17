package com.hedera.services.bdd.spec.transactions.schedule;

/*-
 * ‌
 * Hedera Services Test Clients
 * ​
 * Copyright (C) 2018 - 2020 Hedera Hashgraph, LLC
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
import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import com.hedera.services.bdd.spec.HapiPropertySource;
import com.hedera.services.legacy.proto.utils.CommonUtils;
import com.hederahashgraph.api.proto.java.HederaFunctionality;
import com.hederahashgraph.api.proto.java.ScheduleCreateTransactionBody;
import com.hederahashgraph.api.proto.java.Transaction;
import com.hederahashgraph.api.proto.java.TransactionBody;
import com.hederahashgraph.api.proto.java.TransactionResponse;
import com.hedera.services.bdd.spec.HapiApiSpec;
import com.hedera.services.bdd.spec.transactions.HapiTxnOp;
import com.hederahashgraph.api.proto.java.UncheckedSubmitBody;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

import static com.hederahashgraph.api.proto.java.HederaFunctionality.ScheduleCreate;

public class HapiScheduleCreate<T extends HapiTxnOp<T>> extends HapiTxnOp<HapiScheduleCreate<T>> {
	private static final Logger log = LogManager.getLogger(HapiScheduleCreate.class);

	private boolean scheduleNonsense = false;

	private final String entity;
	private final HapiTxnOp<T> scheduled;

	public HapiScheduleCreate(String scheduled, HapiTxnOp<T> txn) {
		this.entity = scheduled;
		this.scheduled = txn.withLegacyProtoStructure().sansTxnId();
	}

	public HapiScheduleCreate<T> garbled() {
		scheduleNonsense = true;
		return this;
	}

	@Override
	protected HapiScheduleCreate<T> self() {
		return this;
	}

	@Override
	public HederaFunctionality type() {
		return ScheduleCreate;
	}

	@Override
	protected Consumer<TransactionBody.Builder> opBodyDef(HapiApiSpec spec) throws Throwable {
		var subOp = scheduled.signedTxnFor(spec);
		var schedSigMap = subOp.getSigMap();
		if (verboseLoggingOn) {
			var schedTxn = TransactionBody.parseFrom(subOp.getBodyBytes());
			log.info("Scheduling {} with sigs {}", schedTxn, schedSigMap);
		}
		ScheduleCreateTransactionBody opBody = spec
				.txns()
				.<ScheduleCreateTransactionBody, ScheduleCreateTransactionBody.Builder>body(
						ScheduleCreateTransactionBody.class, b -> {
							if (scheduleNonsense) {
								b.setTransactionBody(ByteString.copyFromUtf8("NONSENSE"));
							} else {
								b.setTransactionBody(subOp.getBodyBytes());
							}
							b.setSigMap(schedSigMap);
						}
				);
		return b -> b.setScheduleCreate(opBody);
	}

	@Override
	protected Function<Transaction, TransactionResponse> callToUse(HapiApiSpec spec) {
		return spec.clients().getScheduleSvcStub(targetNodeFor(spec), useTls)::createSchedule;
	}

	@Override
	protected long feeFor(HapiApiSpec spec, Transaction txn, int numPayerKeys) {
		return spec.fees().maxFeeTinyBars();
	}

	@Override
	protected MoreObjects.ToStringHelper toStringHelper() {
		MoreObjects.ToStringHelper helper = super.toStringHelper()
				.add("entity", entity);
		helper.add("id", createdSchedule().orElse("<N/A>"));
		return helper;
	}

	private Optional<String> createdSchedule() {
		return Optional
				.ofNullable(lastReceipt)
				.map(receipt -> HapiPropertySource.asScheduleString(receipt.getScheduleID()));
	}
}