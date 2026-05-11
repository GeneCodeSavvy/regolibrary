package armo_builtins

import future.keywords.contains
import future.keywords.if
import future.keywords.in

has_unmasked_proc_mount(container) if {
	container.securityContext.procMount == "Unmasked"
}

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	container := pod.spec.containers[i]
	has_unmasked_proc_mount(container)

	path := sprintf("spec.containers[%v].securityContext.procMount", [i])

	msga := {
		"alertMessage": sprintf("Pod: %v container %v sets securityContext.procMount to Unmasked", [pod.metadata.name, container.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"fixPaths": [],
		"alertScore": 7,
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

deny contains msga if {
	wl := input[_]
	wl.kind in {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	container := wl.spec.template.spec.containers[i]
	has_unmasked_proc_mount(container)

	path := sprintf("spec.template.spec.containers[%v].securityContext.procMount", [i])

	msga := {
		"alertMessage": sprintf("%v: %v container %v sets securityContext.procMount to Unmasked", [wl.kind, wl.metadata.name, container.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"fixPaths": [],
		"alertScore": 7,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

deny contains msga if {
	cj := input[_]
	cj.kind == "CronJob"
	container := cj.spec.jobTemplate.spec.template.spec.containers[i]
	has_unmasked_proc_mount(container)

	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].securityContext.procMount", [i])

	msga := {
		"alertMessage": sprintf("CronJob: %v container %v sets securityContext.procMount to Unmasked", [cj.metadata.name, container.name]),
		"packagename": "armo_builtins",
		"failedPaths": [path],
		"fixPaths": [],
		"alertScore": 7,
		"alertObject": {"k8sApiObjects": [cj]},
	}
}
