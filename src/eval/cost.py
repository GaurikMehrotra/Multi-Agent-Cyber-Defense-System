"""Cost is unknown unless rates and actual token usage are supplied."""


def estimate(
    input_tokens, output_tokens, input_price_per_million=None, output_price_per_million=None
):
    if input_price_per_million is None or output_price_per_million is None:
        return None
    return (
        input_tokens * input_price_per_million + output_tokens * output_price_per_million
    ) / 1_000_000
