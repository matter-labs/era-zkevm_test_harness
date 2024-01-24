# Geometry config
Contains the geometry ('size') information about circuits.

For example, how many VM iteration steps we do in a single circuit.

This is extracted to a separate crate, as state keepers and others are depending on this information for correct cost estimations, but they don't need to include the whole helper and crypto libraries.