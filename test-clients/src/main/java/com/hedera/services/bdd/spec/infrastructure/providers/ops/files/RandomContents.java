package com.hedera.services.bdd.spec.infrastructure.providers.ops.files;

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

import com.hedera.services.bdd.spec.HapiSpecOperation;
import com.hedera.services.bdd.spec.infrastructure.EntityNameProvider;
import com.hedera.services.bdd.spec.infrastructure.OpProvider;
import com.hedera.services.bdd.spec.queries.QueryVerbs;
import com.hederahashgraph.api.proto.java.FileID;
import com.hederahashgraph.api.proto.java.ResponseCodeEnum;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.DUPLICATE_TRANSACTION;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.FILE_DELETED;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.INSUFFICIENT_TX_FEE;

public class RandomContents implements OpProvider {
	private final ResponseCodeEnum[] permissibleCostAnswerPrechecks = standardQueryPrechecksAnd(
			FILE_DELETED,
			INSUFFICIENT_TX_FEE
	);

	private final ResponseCodeEnum[] permissibleAnswerOnlyPrechecks = standardQueryPrechecksAnd(
			FILE_DELETED,
			INSUFFICIENT_TX_FEE
	);

	private final EntityNameProvider<FileID> files;

	public RandomContents(EntityNameProvider<FileID> files) {
		this.files = files;
	}

	@Override
	public List<HapiSpecOperation> suggestedInitializers() {
		return Collections.emptyList();
	}

	@Override
	public Optional<HapiSpecOperation> get() {
		final var target = files.getQualifying();
		if (target.isEmpty()) {
			return Optional.empty();
		}

		var op = QueryVerbs.getFileContents(target.get())
				.payingWith(FUNDING_ACCOUNT)
				.hasCostAnswerPrecheckFrom(permissibleCostAnswerPrechecks)
				.hasAnswerOnlyPrecheckFrom(permissibleAnswerOnlyPrechecks);

		return Optional.of(op);
	}
}
