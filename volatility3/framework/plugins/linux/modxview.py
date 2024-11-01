# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List, Dict, Set, Iterator
from volatility3.plugins.linux import lsmod, check_modules, hidden_modules
from volatility3.framework import interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints, TreeGrid, NotAvailableValue
from volatility3.framework.symbols.linux import extensions
from volatility3.framework.constants import architectures

vollog = logging.getLogger(__name__)


class Modxview(interfaces.plugins.PluginInterface):
    """Centralize lsmod, check_modules and hidden_modules results to efficiently
    spot modules presence and taints."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 11, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=architectures.LINUX_ARCHS,
            ),
            requirements.PluginRequirement(
                name="lsmod", plugin=lsmod.Lsmod, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="check_modules",
                plugin=check_modules.Check_modules,
                version=(0, 0, 0),
            ),
            requirements.PluginRequirement(
                name="hidden_modules",
                plugin=hidden_modules.Hidden_modules,
                version=(1, 0, 0),
            ),
            requirements.BooleanRequirement(
                name="plain_taints",
                description="Display the plain taints string for each module.",
                optional=True,
                default=False,
            ),
        ]

    @classmethod
    def run_lsmod(
        cls, context: interfaces.context.ContextInterface, kernel_name: str
    ) -> List[extensions.module]:
        """Wrapper for the lsmod plugin."""
        return list(lsmod.Lsmod.list_modules(context, kernel_name))

    @classmethod
    def run_check_modules(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_name: str,
    ) -> List[extensions.module]:
        """Wrapper for the check_modules plugin.
        Here, we extract the /sys/module/ list."""
        kernel = context.modules[kernel_name]
        sysfs_modules: dict = check_modules.Check_modules.get_kset_modules(
            context, kernel_name
        )

        # Convert get_kset_modules() offsets back to module objects
        return [
            kernel.object(object_type="module", offset=m_offset, absolute=True)
            for m_offset in sysfs_modules.values()
        ]

    @classmethod
    def run_hidden_modules(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_name: str,
        known_modules_addresses: Set[int],
    ) -> List[extensions.module]:
        """Wrapper for the hidden_modules plugin."""
        modules_memory_boundaries = (
            hidden_modules.Hidden_modules.get_modules_memory_boundaries(
                context, kernel_name
            )
        )
        return list(
            hidden_modules.Hidden_modules.get_hidden_modules(
                context,
                kernel_name,
                known_modules_addresses,
                modules_memory_boundaries,
            )
        )

    @classmethod
    def flatten_run_modules_results(
        cls, run_results: Dict[str, List[extensions.module]], deduplicate: bool = True
    ) -> Iterator[extensions.module]:
        """Flatten a dictionary mapping plugin names and modules list, to a single merged list.
        This is useful to get a generic lookup list of all the detected modules.

        Args:
            run_results: dictionary of plugin names mapping a list of detected modules
            deduplicate: remove duplicate modules, based on their offsets

        Returns:
            Iterator of modules objects
        """
        seen_addresses = set()
        for modules in run_results.values():
            for module in modules:
                if deduplicate and module.vol.offset in seen_addresses:
                    continue
                seen_addresses.add(module.vol.offset)
                yield module

    @classmethod
    def run_modules_scanners(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_name: str,
        run_hidden_modules: bool = True,
    ) -> Dict[str, List[extensions.module]]:
        """Run module scanning plugins and aggregate the results.

        Args:
            run_hidden_modules: specify if the hidden_modules plugin should be run
        Returns:
            Dictionary mapping each plugin to its corresponding result
        """

        kernel = context.modules[kernel_name]
        run_results = {}
        run_results["lsmod"] = cls.run_lsmod(context, kernel_name)
        run_results["check_modules"] = cls.run_check_modules(context, kernel_name)
        if run_hidden_modules:
            known_module_addresses = set(
                context.layers[kernel.layer_name].canonicalize(module.vol.offset)
                for module in run_results["lsmod"] + run_results["check_modules"]
            )
            run_results["hidden_modules"] = cls.run_hidden_modules(
                context, kernel_name, known_module_addresses
            )

        return run_results

    def _generator(self):
        kernel_name = self.config["kernel"]
        run_results = self.run_modules_scanners(self.context, kernel_name)
        modules_offsets = {}
        for key in ["lsmod", "check_modules", "hidden_modules"]:
            modules_offsets[key] = set(module.vol.offset for module in run_results[key])

        seen_addresses = set()
        for modules_list in run_results.values():
            for module in modules_list:
                if module.vol.offset in seen_addresses:
                    continue
                seen_addresses.add(module.vol.offset)

                if self.config.get("plain_taints"):
                    taints = module.get_taints_as_plain_string()
                else:
                    taints = ",".join(module.get_taints_parsed())

                yield (
                    0,
                    (
                        module.get_name() or NotAvailableValue(),
                        format_hints.Hex(module.vol.offset),
                        module.vol.offset in modules_offsets["lsmod"],
                        module.vol.offset in modules_offsets["check_modules"],
                        module.vol.offset in modules_offsets["hidden_modules"],
                        taints or NotAvailableValue(),
                    ),
                )

    def run(self):
        columns = [
            ("Name", str),
            ("Address", format_hints.Hex),
            ("In /proc/modules", bool),
            ("In /sys/module/", bool),
            ("Hidden", bool),
            ("Taints", str),
        ]

        return TreeGrid(
            columns,
            self._generator(),
        )
