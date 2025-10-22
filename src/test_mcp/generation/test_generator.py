"""Test generator using Claude for creating conversational tests"""

import json
import logging
import re

import anthropic

from ..models.conversational import ConversationalTestConfig
from .models import GenerationRequest, ServerContext


class TestGenerator:
    """Generates conversational test cases using Claude"""

    def __init__(self, anthropic_api_key: str):
        self.client = anthropic.Anthropic(api_key=anthropic_api_key)
        self.logger = logging.getLogger(__name__)

    def _clean_json(self, json_str: str) -> str:
        """Clean common JSON issues from LLM-generated content"""
        # Remove trailing commas before closing brackets/braces
        json_str = re.sub(r",(\s*[}\]])", r"\1", json_str)
        # Remove comments (// and /* */) but NOT URLs (e.g., https://)
        # Only remove // if it's not preceded by : (to avoid matching URLs)
        json_str = re.sub(r"(?<!:)//.*?$", "", json_str, flags=re.MULTILINE)
        json_str = re.sub(r"/\*.*?\*/", "", json_str, flags=re.DOTALL)
        return json_str

    def _calculate_num_tests(self, context: ServerContext) -> int:
        """Calculate optimal number of tests based on discovered capabilities

        Limits: Max 20 for tools/resources/prompts + always 5 integration tests
        """
        num_tools = len(context.mcp_tools)
        num_resources = len(context.mcp_resources)
        num_prompts = len(context.mcp_prompts)

        # Generate tests: 6 per tool (1 happy path + 5 edge cases),
        # 6 per resource (1 valid + 5 edge cases), 1 per prompt
        # Plus 5 integration tests
        estimated_non_integration = (num_tools * 6) + (num_resources * 6) + num_prompts

        # Apply limit: max 20 for non-integration tests
        capped_non_integration = min(estimated_non_integration, 20)

        # Always add 5 integration tests
        return capped_non_integration + 5

    def _build_test_queue(self, context: ServerContext) -> list[dict]:
        """Build ordered queue of test specifications to generate

        Limits:
        - Maximum 20 tests for tools/resources/prompts combined
        - Always 5 integration tests
        """
        queue = []
        MAX_NON_INTEGRATION_TESTS = 20
        INTEGRATION_TEST_COUNT = 5

        # Build full queue first
        tool_tests = []
        for tool in context.mcp_tools:
            tool_tests.append({"type": "happy_path", "tool": tool.name, "variant": 1})
            tool_tests.extend(
                {"type": "edge_case", "tool": tool.name, "variant": i}
                for i in range(1, 6)
            )

        resource_tests = []
        for resource in context.mcp_resources:
            resource_tests.append(
                {"type": "happy_path", "resource": resource.name, "variant": 1}
            )
            resource_tests.extend(
                {"type": "edge_case", "resource": resource.name, "variant": i}
                for i in range(1, 6)
            )

        prompt_tests = [
            {"type": "happy_path", "prompt": prompt, "variant": 1}
            for prompt in context.mcp_prompts
        ]

        # Calculate total non-integration tests
        total_tests = len(tool_tests) + len(resource_tests) + len(prompt_tests)

        # Apply limit if exceeded
        if total_tests > MAX_NON_INTEGRATION_TESTS:
            # Proportionally reduce each category
            ratio = MAX_NON_INTEGRATION_TESTS / total_tests

            tool_limit = max(1, int(len(tool_tests) * ratio)) if tool_tests else 0
            resource_limit = max(1, int(len(resource_tests) * ratio)) if resource_tests else 0
            prompt_limit = max(1, int(len(prompt_tests) * ratio)) if prompt_tests else 0

            # Adjust if we're still over the limit
            current_total = tool_limit + resource_limit + prompt_limit
            if current_total > MAX_NON_INTEGRATION_TESTS:
                # Trim from the largest category
                if tool_limit >= resource_limit and tool_limit >= prompt_limit:
                    tool_limit -= (current_total - MAX_NON_INTEGRATION_TESTS)
                elif resource_limit >= prompt_limit:
                    resource_limit -= (current_total - MAX_NON_INTEGRATION_TESTS)
                else:
                    prompt_limit -= (current_total - MAX_NON_INTEGRATION_TESTS)

            tool_tests = tool_tests[:tool_limit]
            resource_tests = resource_tests[:resource_limit]
            prompt_tests = prompt_tests[:prompt_limit]

        # Add all tests to queue
        queue.extend(tool_tests)
        queue.extend(resource_tests)
        queue.extend(prompt_tests)

        # Always add exactly 5 integration tests
        queue.extend(
            {"type": "integration", "variant": i}
            for i in range(1, INTEGRATION_TEST_COUNT + 1)
        )

        return queue

    def _get_test_spec_description(self, test_spec: dict) -> str:
        """Generate human-readable description of test specification"""
        test_type = test_spec["type"]
        variant = test_spec.get("variant", 1)

        if "tool" in test_spec:
            target = f"tool '{test_spec['tool']}'"
        elif "resource" in test_spec:
            target = f"resource '{test_spec['resource']}'"
        elif "prompt" in test_spec:
            target = f"prompt '{test_spec['prompt']}'"
        else:
            target = "multiple capabilities"

        if test_type == "happy_path":
            return f"happy path test for {target}"
        elif test_type == "edge_case":
            return f"edge case {variant} for {target}"
        else:  # integration
            return f"integration test {variant} combining {target}"

    def _build_targeted_context(self, test_spec: dict, context: ServerContext) -> str:
        """Build minimal context containing only relevant information for this test.

        TOKEN OPTIMIZATION: Instead of including all tools, resources, and documentation
        for every test generation, we only include what's needed for the specific test.
        This can reduce input tokens by 60-80% compared to full context approach.
        """
        if "tool" in test_spec:
            # Only include the specific tool being tested
            tool = next(
                (t for t in context.mcp_tools if t.name == test_spec["tool"]), None
            )
            if tool:
                return f"### Tool Being Tested:\n{self._format_single_tool(tool)}"
            return ""
        elif "resource" in test_spec:
            # Only include the specific resource being tested
            resource = next(
                (r for r in context.mcp_resources if r.name == test_spec["resource"]),
                None,
            )
            if resource:
                return f"### Resource Being Tested:\n{self._format_single_resource(resource)}"
            return ""
        elif "prompt" in test_spec:
            # Only include the specific prompt being tested
            return f"### Prompt Being Tested:\n{test_spec['prompt']}"
        else:
            # Integration test - include summary of all capabilities
            tools_list = ", ".join(t.name for t in context.mcp_tools)
            resources_list = ", ".join(r.name for r in context.mcp_resources)
            return f"### Available Capabilities:\nTools: {tools_list}\nResources: {resources_list}"

    def _build_single_test_prompt(
        self, test_spec: dict, request: GenerationRequest, context: ServerContext
    ) -> str:
        """Build prompt for generating a single test case.

        TOKEN OPTIMIZATIONS APPLIED:
        1. Context-aware prompts: Only include relevant tool/resource (60-80% reduction)
        2. Compact JSON schemas: No indentation (20-30% reduction)
        3. Streamlined instructions: Concise directives (30-40% reduction)
        4. Minimal output format: One-line specification (15-25% reduction)
        5. No documentation bloat: Remove research/docs sections (40-60% reduction)

        Total estimated reduction: 70-85% fewer tokens vs. full context approach.
        """
        # Use targeted context instead of full context
        targeted_context = self._build_targeted_context(test_spec, context)

        # Simplified test requirements
        user_intent_line = (
            f"Focus: {request.user_intent}" if request.user_intent else ""
        )

        # Build specific test instructions based on spec
        test_description = self._get_test_spec_description(test_spec)

        if test_spec["type"] == "happy_path":
            test_instructions = self._get_happy_path_instructions(test_spec)
        elif test_spec["type"] == "edge_case":
            test_instructions = self._get_edge_case_instructions(test_spec)
        else:  # integration
            test_instructions = self._get_integration_instructions(test_spec)

        return f"""Generate conversational test for MCP server.

{targeted_context}

{user_intent_line}

Task: {test_description}
{test_instructions}

Output format: Return ONLY a valid JSON object (no markdown, no other text) with this structure:
{{
  "test_id": "descriptive_test_name",
  "user_message": "Natural user message to start conversation",
  "success_criteria": "Single clear criterion for success - NOT an array",
  "max_turns": 5,
  "context_persistence": true,
  "metadata": {{
    "tool_name": "tool_name",
    "test_type": "happy_path"
  }}
}}

CRITICAL: success_criteria must be a single string, NOT an array of strings. Combine multiple criteria into one cohesive sentence."""

    def _get_happy_path_instructions(self, test_spec: dict) -> str:
        """Get instructions for happy path test"""
        if "tool" in test_spec:
            return f"Happy path test for **{test_spec['tool']}**: valid inputs, typical use case, 3-6 turns, success = tool executes correctly"
        elif "resource" in test_spec:
            return f"Happy path test for **{test_spec['resource']}**: valid access, realistic use, 3-6 turns, success = resource retrieved"
        else:  # prompt
            return f"Test **{test_spec['prompt']}** prompt: realistic invocation, 3-5 turns, clear success criteria"

    def _get_edge_case_instructions(self, test_spec: dict) -> str:
        """Get instructions for edge case test"""
        variant = test_spec.get("variant", 1)
        edge_cases = [
            "invalid params",
            "boundary conditions",
            "error scenarios",
            "malformed data",
            "unexpected types/special chars",
        ]

        focus = edge_cases[variant - 1] if variant <= len(edge_cases) else edge_cases[0]
        target = f"**{test_spec.get('tool') or test_spec.get('resource')}**"

        return f"Edge case #{variant} for {target}: focus={focus}, verify error handling, 4-7 turns"

    def _get_integration_instructions(self, test_spec: dict) -> str:
        """Get instructions for integration test"""
        variant = test_spec.get("variant", 1)
        focus_options = [
            "sequential usage of multiple capabilities",
            "complex workflow combining tools and resources",
            "error recovery across multiple operations",
            "state management in multi-step process",
            "end-to-end realistic user scenario"
        ]
        focus = focus_options[variant - 1] if variant <= len(focus_options) else focus_options[0]
        return f"Integration test #{variant}: {focus}, 2+ tools/resources, multi-step scenario, 8-12 turns"

    async def _generate_single_test(
        self, test_spec: dict, request: GenerationRequest, context: ServerContext
    ) -> tuple[ConversationalTestConfig | None, dict]:
        """Generate a single test case, returns (test, usage_stats)"""
        usage_stats = {
            "input_tokens": 0,
            "output_tokens": 0,
            "success": False,
        }

        try:
            prompt = self._build_single_test_prompt(test_spec, request, context)

            # Make API call with response object for token tracking
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,  # Lower limit since we're generating single test
                temperature=0.3,
                messages=[{"role": "user", "content": prompt}],
            )

            # Extract token usage
            if response.usage:
                usage_stats["input_tokens"] = response.usage.input_tokens
                usage_stats["output_tokens"] = response.usage.output_tokens

            # Get response text
            if not response or not response.content:
                self.logger.warning("Empty response from API for single test")
                return None, usage_stats

            original_text = response.content[0].text if response.content else "{}"

            # Parse JSON
            result_text = self._extract_json_from_response(original_text)
            result_text = self._find_json_object(result_text)
            result_text = self._clean_json(result_text)

            # Parse and create test config
            test_data = json.loads(result_text)

            # Handle success_criteria if it's an array (shouldn't happen, but defensive)
            if isinstance(test_data.get("success_criteria"), list):
                self.logger.warning(
                    "success_criteria was an array, converting to string"
                )
                test_data["success_criteria"] = " AND ".join(
                    str(c) for c in test_data["success_criteria"]
                )

            test = ConversationalTestConfig(**test_data)

            usage_stats["success"] = True
            return test, usage_stats

        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse JSON for test: {e}")
            self.logger.debug(f"Response was: {result_text[:200]}...")
            return None, usage_stats
        except Exception as e:
            self.logger.warning(f"Failed to generate single test: {e}")
            return None, usage_stats

    async def _make_api_request(self, prompt: str) -> str:
        """Make API request to Claude and return raw response text"""
        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=8000,
            temperature=0.3,
            messages=[{"role": "user", "content": prompt}],
        )

        if not response or not response.content:
            self.logger.error("Empty response from API")
            return "[]"

        return response.content[0].text if response.content else "[]"

    def _extract_json_from_response(self, result_text: str) -> str:
        """Extract JSON from markdown code blocks or text"""
        if "```json" in result_text:
            start = result_text.find("```json") + 7
            end = result_text.find("```", start)
            if end == -1:
                self.logger.warning(
                    "Found ```json but no closing ```, using rest of text"
                )
                return result_text[start:].strip()
            return result_text[start:end].strip()

        if "```" in result_text:
            start = result_text.find("```") + 3
            end = result_text.find("```", start)
            if end == -1:
                self.logger.warning("Found ``` but no closing ```, using rest of text")
                return result_text[start:].strip()
            return result_text[start:end].strip()

        return result_text

    def _find_json_array(self, result_text: str) -> str:
        """Find JSON array in text if it doesn't start with '['"""
        if not result_text.strip().startswith("["):
            self.logger.warning(
                "Response doesn't start with '[', trying to find JSON array"
            )
            array_start = result_text.find("[")
            if array_start != -1:
                self.logger.info(f"Found JSON array at position {array_start}")
                return result_text[array_start:]

        return result_text

    def _find_json_object(self, result_text: str) -> str:
        """Find JSON object in text if it doesn't start with '{'"""
        if not result_text.strip().startswith("{"):
            self.logger.debug(
                "Response doesn't start with '{', trying to find JSON object"
            )
            obj_start = result_text.find("{")
            if obj_start != -1:
                self.logger.debug(f"Found JSON object at position {obj_start}")
                return result_text[obj_start:]

        return result_text

    def _validate_json_completeness(self, result_text: str) -> None:
        """Check if JSON appears complete"""
        if not result_text.rstrip().endswith("]"):
            self.logger.warning(
                "JSON response appears incomplete (doesn't end with ]). "
                "Response may have been truncated due to token limits."
            )

    def _convert_to_test_configs(
        self, tests_data: list[dict]
    ) -> list[ConversationalTestConfig]:
        """Convert parsed JSON data to ConversationalTestConfig objects"""
        tests = []
        for i, test_data in enumerate(tests_data, 1):
            try:
                test = ConversationalTestConfig(**test_data)
                tests.append(test)
                self._log_test_creation(test, i)
            except Exception as e:
                self.logger.warning(f"   ✗ Failed to parse test case {i}: {e}")
                continue

        return tests

    def _log_test_creation(self, test: ConversationalTestConfig, index: int) -> None:
        """Log successful test case creation"""
        test_type = (
            test.metadata.get("test_type", "unknown") if test.metadata else "unknown"
        )
        tool_name = test.metadata.get("tool_name", "") if test.metadata else ""
        resource_name = test.metadata.get("resource_name", "") if test.metadata else ""

        target = tool_name or resource_name or "integration"
        self.logger.info(f"   ✓ Test {index}: {test.test_id} ({test_type} - {target})")

    def _handle_json_error(
        self, error: json.JSONDecodeError, result_text: str, original_text: str
    ) -> None:
        """Handle JSON parsing errors and save debug information"""
        import os
        import uuid
        from datetime import datetime

        self.logger.error(f"Failed to parse generated tests JSON: {error}")

        debug_dir = "test_results/debug"
        os.makedirs(debug_dir, exist_ok=True)

        # Add collision safety with microseconds and unique ID
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[
            :-3
        ]  # Include milliseconds
        unique_id = uuid.uuid4().hex[:8]
        debug_file = os.path.join(debug_dir, f"json_error_{timestamp}_{unique_id}.txt")

        self._save_debug_file(debug_file, error, result_text, original_text)
        self._log_error_context(error, result_text)

        self.logger.error(f"Full response saved to: {debug_file}")
        self.logger.debug(f"Response preview: {result_text[:500]}...")

    def _save_debug_file(
        self,
        debug_file: str,
        error: json.JSONDecodeError,
        result_text: str,
        original_text: str,
    ) -> None:
        """Save debug information to file"""
        with open(debug_file, "w") as f:
            f.write(f"JSON Parse Error: {error}\n")
            f.write("=" * 80 + "\n")
            f.write("ORIGINAL Claude Response:\n")
            f.write("=" * 80 + "\n")
            f.write(original_text)
            f.write("\n\n")
            f.write("=" * 80 + "\n")
            f.write("EXTRACTED JSON (after processing):\n")
            f.write("=" * 80 + "\n")
            f.write(result_text)
            f.write("\n\n")
            f.write("=" * 80 + "\n")
            f.write("DIAGNOSTIC INFO:\n")
            f.write("=" * 80 + "\n")
            f.write(f"Response length: {len(result_text)} characters\n")
            f.write(f"Ends with ']': {result_text.rstrip().endswith(']')}\n")
            f.write(f"Likely truncated: {not result_text.rstrip().endswith(']')}\n")

    def _log_error_context(self, error: json.JSONDecodeError, result_text: str) -> None:
        """Log context around JSON parsing error"""
        if hasattr(error, "pos"):
            error_pos = error.pos
            context_start = max(0, error_pos - 200)
            context_end = min(len(result_text), error_pos + 200)
            context = result_text[context_start:context_end]

            self.logger.error(f"Context around error position {error_pos}:")
            self.logger.error(f"...{context}...")

        if not result_text.rstrip().endswith("]"):
            self.logger.error(
                "Response appears truncated. This may indicate max_tokens is too low "
                "for the number of test cases requested."
            )

    async def generate_tests(
        self, request: GenerationRequest, context: ServerContext, status=None
    ) -> list[ConversationalTestConfig]:
        """Generate test cases iteratively, one at a time, with token monitoring"""
        # Build test queue
        test_queue = self._build_test_queue(context)
        total_tests = len(test_queue)

        self.logger.info(f"📋 Test generation queue: {total_tests} tests planned")
        self.logger.info("")

        if status:
            status.update(f"Generating {total_tests} test cases (one at a time)")

        # Initialize tracking
        successful_tests = []
        token_tracking = {
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_requests": 0,
            "successful_tests": 0,
            "failed_tests": 0,
        }

        # Generate tests iteratively
        for i, test_spec in enumerate(test_queue, 1):
            test_description = self._get_test_spec_description(test_spec)
            self.logger.info(
                f"🔨 Generating test {i}/{total_tests}: {test_description}"
            )

            # Update status periodically
            if status and i % 5 == 0:
                status.update(f"Generated {i}/{total_tests} tests")

            # Generate single test
            test, usage = await self._generate_single_test(test_spec, request, context)

            # Track token usage
            token_tracking["total_input_tokens"] += usage["input_tokens"]
            token_tracking["total_output_tokens"] += usage["output_tokens"]
            token_tracking["total_requests"] += 1

            # Log token usage
            self.logger.debug(
                f"   Tokens: {usage['input_tokens']} input, "
                f"{usage['output_tokens']} output"
            )

            # Handle result
            if test and usage["success"]:
                successful_tests.append(test)
                token_tracking["successful_tests"] += 1
                self._log_test_creation(test, i)
            else:
                token_tracking["failed_tests"] += 1
                self.logger.warning(f"   ✗ Failed to generate test {i}")
                # Continue with next test
                continue

        # Log summary statistics
        self._log_generation_summary(token_tracking, total_tests)

        return successful_tests

    def _log_generation_summary(self, tracking: dict, total_planned: int) -> None:
        """Log comprehensive summary of test generation"""
        self.logger.info("")
        self.logger.info("=" * 70)
        self.logger.info("📊 Test Generation Summary")
        self.logger.info("=" * 70)
        self.logger.info(
            f"✅ Successfully generated: {tracking['successful_tests']}/{total_planned} tests"
        )

        if tracking["failed_tests"] > 0:
            self.logger.info(f"❌ Failed: {tracking['failed_tests']} tests")

        self.logger.info(f"📡 API requests made: {tracking['total_requests']}")
        self.logger.info(
            f"🔤 Total tokens used: {tracking['total_input_tokens'] + tracking['total_output_tokens']:,}"
        )
        self.logger.info(f"   • Input tokens: {tracking['total_input_tokens']:,}")
        self.logger.info(f"   • Output tokens: {tracking['total_output_tokens']:,}")

        if tracking["successful_tests"] > 0:
            avg_total = (
                tracking["total_input_tokens"] + tracking["total_output_tokens"]
            ) / tracking["successful_tests"]
            self.logger.info(f"   • Average per test: {avg_total:.0f} tokens")

        self.logger.info("=" * 70)
        self.logger.info("")

    def _format_single_tool(self, tool) -> str:
        """Format a single tool with compact schema"""
        result = f"**{tool.name}**\n"
        if tool.description:
            result += f"Description: {tool.description}\n"
        if tool.input_schema:
            result += (
                f"Schema: {json.dumps(tool.input_schema, separators=(',', ':'))}\n"
            )
        return result

    def _format_single_resource(self, resource) -> str:
        """Format a single resource"""
        result = f"**{resource.name}** ({resource.uri})\n"
        if resource.description:
            result += f"Description: {resource.description}\n"
        return result

    def _format_tools_section(self, context: ServerContext) -> str:
        """Format tools section of the prompt"""
        tools_section = "### Available MCP Tools:\n"
        if not context.mcp_tools:
            tools_section += "No tools discovered.\n"
        else:
            for tool in context.mcp_tools:
                tools_section += f"\n**{tool.name}**\n"
                if tool.description:
                    tools_section += f"Description: {tool.description}\n"
                if tool.input_schema:
                    # Compact JSON formatting (no indentation)
                    tools_section += f"Schema: {json.dumps(tool.input_schema, separators=(',', ':'))}\n"
        return tools_section

    def _format_resources_section(self, context: ServerContext) -> str:
        """Format resources section of the prompt"""
        if not context.mcp_resources:
            return ""

        resources_section = "\n### Available MCP Resources:\n"
        for resource in context.mcp_resources:
            resources_section += f"\n**{resource.name}** ({resource.uri})\n"
            if resource.description:
                resources_section += f"Description: {resource.description}\n"
        return resources_section

    def _format_prompts_section(self, context: ServerContext) -> str:
        """Format prompts section of the prompt"""
        if not context.mcp_prompts:
            return ""

        prompts_section = "\n### Available MCP Prompts:\n"
        for prompt in context.mcp_prompts:
            prompts_section += f"- {prompt}\n"
        return prompts_section

    def _format_documentation_section(self, context: ServerContext) -> str:
        """Format documentation insights section"""
        if not context.documentation_content:
            return ""

        section = "\n### Documentation Insights:\n"
        for doc in context.documentation_content:
            section += f"\n{doc}\n"
        return section

    def _format_example_workflows_section(self, context: ServerContext) -> str:
        """Format example workflows section"""
        if not context.example_workflows:
            return ""

        section = "\n### Example Workflows:\n"
        for workflow in context.example_workflows:
            section += f"- {workflow}\n"
        return section

    def _format_web_findings_section(self, context: ServerContext) -> str:
        """Format web research findings section"""
        if not context.web_findings:
            return ""

        section = "\n### Research Findings:\n"

        if context.web_findings.usage_patterns:
            section += "\nCommon patterns:\n"
            for pattern in context.web_findings.usage_patterns:
                section += f"- {pattern}\n"

        if context.web_findings.best_practices:
            section += "\nBest practices:\n"
            for practice in context.web_findings.best_practices:
                section += f"- {practice}\n"

        if context.web_findings.limitations:
            section += "\nLimitations:\n"
            for limitation in context.web_findings.limitations:
                section += f"- {limitation}\n"

        return section

    def _format_context_section(self, context: ServerContext) -> str:
        """Format complete context section combining all research findings"""
        sections = [
            self._format_documentation_section(context),
            self._format_example_workflows_section(context),
            self._format_web_findings_section(context),
        ]
        return "".join(s for s in sections if s)

    def _get_prompt_header(self, context: ServerContext) -> str:
        """Get the header section of the prompt"""
        tools_section = self._format_tools_section(context)
        resources_section = self._format_resources_section(context)
        prompts_section = self._format_prompts_section(context)
        context_section = self._format_context_section(context)

        return f"""You are an expert at creating conversational tests for MCP servers.

## Server Information:
{context.research_summary}

{tools_section}
{resources_section}
{prompts_section}

{context_section}"""

    def _get_test_requirements(self, request: GenerationRequest) -> str:
        """Get testing focus and custom notes section"""
        custom_notes = (
            chr(10).join(f"- {note}" for note in request.custom_notes)
            if request.custom_notes
            else "None"
        )

        return f"""## Testing Focus:
{request.user_intent}

## Custom Notes:
{custom_notes}"""

    def _get_coverage_requirements(self, num_tests: int) -> str:
        """Get coverage requirements section"""
        return f"""## Task:
Generate {num_tests} comprehensive conversational test cases that:

**Coverage Requirements:**
- Create 6 tests for EACH tool:
  1. ONE happy path test (valid inputs, successful execution)
  2. FIVE edge case tests covering:
     - Invalid input parameters
     - Boundary conditions (min/max values, empty inputs)
     - Error scenarios (non-existent resources, timeouts)
     - Malformed data
     - Unexpected data types
- Create 6 tests for EACH resource:
  1. ONE valid resource access test
  2. FIVE edge case tests (non-existent resources, invalid access patterns, permissions, etc.)
- Create 1 test for EACH prompt
- Maximum 20 tests for tools/resources/prompts combined
- Include exactly 5 integration tests that combine multiple tools/resources
- CRITICAL: Generate diverse, comprehensive edge cases for every capability

**Test Complexity Guidelines:**
- Happy path tests: 3-6 turns
- Edge case tests: 4-7 turns (each edge case should be a separate test)
- Integration tests: 8-12 turns

**Quality Requirements:**
- Clear, measurable success criteria
- Realistic user scenarios
- Natural conversation flow
- Proper error handling expectations
- Test names should clearly indicate what is being tested"""

    def _get_format_specification(self) -> str:
        """Get JSON format specification for test cases"""
        return """## Output Format:
Return a JSON array of test cases. Each test case must have:
- test_id: string (descriptive, snake_case, e.g., "tool_name_happy_path" or "tool_name_edge_cases")
- user_message: string (natural user message to start conversation)
- success_criteria: string (clear criteria for LLM judge)
- max_turns: integer (appropriate for complexity)
- context_persistence: boolean (usually true)
- metadata: object with:
  - tool_name: string (name of the tool being tested, if applicable)
  - resource_name: string (name of the resource being tested, if applicable)
  - prompt_name: string (name of the prompt being tested, if applicable)
  - test_type: string ("happy_path", "edge_cases", or "integration")"""

    def _get_example_test_cases(self) -> str:
        """Get example test cases to guide generation"""
        return """## Examples of Good Test Cases:

```json
[
  {
    "test_id": "fetch_url_happy_path",
    "user_message": "Can you fetch the content from https://example.com for me?",
    "success_criteria": "Agent successfully uses fetch_url tool and returns the content",
    "max_turns": 5,
    "context_persistence": true,
    "metadata": {
      "tool_name": "fetch_url",
      "test_type": "happy_path"
    }
  },
  {
    "test_id": "fetch_url_invalid_url",
    "user_message": "Please fetch content from an invalid URL: not-a-valid-url",
    "success_criteria": "Agent handles invalid URL gracefully, explains the error, and suggests corrections",
    "max_turns": 6,
    "context_persistence": true,
    "metadata": {
      "tool_name": "fetch_url",
      "test_type": "edge_cases"
    }
  },
  {
    "test_id": "fetch_url_empty_url",
    "user_message": "Fetch content from an empty URL",
    "success_criteria": "Agent handles empty URL parameter, provides helpful error message",
    "max_turns": 5,
    "context_persistence": true,
    "metadata": {
      "tool_name": "fetch_url",
      "test_type": "edge_cases"
    }
  },
  {
    "test_id": "fetch_url_nonexistent_domain",
    "user_message": "Fetch https://this-domain-definitely-does-not-exist-12345.com",
    "success_criteria": "Agent handles DNS resolution failure appropriately",
    "max_turns": 6,
    "context_persistence": true,
    "metadata": {
      "tool_name": "fetch_url",
      "test_type": "edge_cases"
    }
  },
  {
    "test_id": "fetch_url_timeout",
    "user_message": "Fetch content from a very slow server that might timeout",
    "success_criteria": "Agent handles timeout scenarios and provides user-friendly response",
    "max_turns": 7,
    "context_persistence": true,
    "metadata": {
      "tool_name": "fetch_url",
      "test_type": "edge_cases"
    }
  },
  {
    "test_id": "fetch_url_malformed_response",
    "user_message": "Fetch content from a URL that returns malformed data",
    "success_criteria": "Agent handles malformed responses without crashing, provides helpful feedback",
    "max_turns": 6,
    "context_persistence": true,
    "metadata": {
      "tool_name": "fetch_url",
      "test_type": "edge_cases"
    }
  },
  {
    "test_id": "summarize_code_prompt",
    "user_message": "Please use the 'summarize_code' prompt to help me understand this function",
    "success_criteria": "Agent successfully invokes the MCP prompt and provides helpful code summary",
    "max_turns": 5,
    "context_persistence": true,
    "metadata": {
      "prompt_name": "summarize_code",
      "test_type": "happy_path"
    }
  },
  {
    "test_id": "multi_tool_integration",
    "user_message": "I need to fetch data from multiple sources and compare them",
    "success_criteria": "Agent uses multiple tools in sequence, handles results properly",
    "max_turns": 10,
    "context_persistence": true,
    "metadata": {
      "test_type": "integration"
    }
  }
]
```"""

    def _get_output_format_section(self) -> str:
        """Get output format and examples section"""
        format_spec = self._get_format_specification()
        examples = self._get_example_test_cases()
        return f"{format_spec}\n\n{examples}"

    def _build_generation_prompt(
        self, request: GenerationRequest, context: ServerContext, num_tests: int
    ) -> str:
        """Build comprehensive prompt for test generation"""
        prompt_header = self._get_prompt_header(context)
        test_requirements = self._get_test_requirements(request)
        coverage_requirements = self._get_coverage_requirements(num_tests)
        output_format = self._get_output_format_section()

        return f"""{prompt_header}

{test_requirements}

{coverage_requirements}

{output_format}

Generate {num_tests} test cases now. Return ONLY valid JSON array, no other text."""
